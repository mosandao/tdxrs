"""通达信新一代 7709 行情协议客户端（纯 Python，零依赖）。

背景：2026-07 起通达信服务端对 pytdx 系旧帧（0c 02 系）断供行情数据
（TCP 通、目录/财务类照常应答，快照/K线/分时/除权静默返回空），官方
客户端改用本文实现的新帧格式。逆向结论（2026-09-14，线缆级验证）：

- 无握手密钥、无加密：裸 TCP + 正确帧格式即返回数据；登录帧为静态
  字节串（80B），可跨连接重放；
- 响应帧：[4B 魔数 b1 cb 74 00][u16 方法回显][8B][u16 载荷长][u16 载荷长回显]，
  载荷长位于 offset 12（LE u16），总长 = 16 + 载荷长；
- 日K记录 36B：[u32 日期 YYYYMMDD][f32 保留][f32 开][f32 高][f32 低][f32 收]
  [f32 成交额(元)][u32 成交量(股)][f32 流通股本(万股)]；载荷尾部 120B 为 GBK 名称区；
- 市场字节：1=沪 0=深（与老协议一致）。

请求帧模板取自官方客户端抓包原文（见 research/），代码字段以哨兵
``C0DE00`` 占位，发送前替换为实际市场字节 + 6 位代码。
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

MAGIC_RSP = b"\xb1\xcb\x74\x00"
HEADER_LEN = 16
CODE_SENTINEL = b"C0DE00"

MARKET_SH = 1
MARKET_SZ = 0

# 周期类别：日线=4（与老协议 KLINE_DAILY 同源）；其余周期字段位待逐一验证
KLINE_DAY = 4

_DEFAULT_HOST = "121.36.248.138"

# 登录帧 80B（官方客户端建连后约 55ms 发出）
_BARS = bytes.fromhex(
    "000a00681301300030002e120000433044453030000000000000000000000000" + "000000000400010000000000bc02000001010001000000000000"
)  # 58B 代码@14 市场@12
_MINUTE = bytes.fromhex(
    "0007003a0101280028002d120000433044453030000000000000000000000000" + "000000000000000001000000000000000000"
)  # 50B 代码@14 市场@12
_QUOTE = bytes.fromhex(
    "000500290001300030002b12ffffffffff58ff07000000020000000000000000" + "0100000043304445303000000000000000000000000000000000"
)  # 58B 代码@36 市场@34
_SNAPSHOT = bytes.fromhex(
    "000d002c12012d002d002c12060000000000000000000000000e00360000001b" + "000100fffce1cc3f080302000000000000000000000001"
)  # 55B
_LOGIN = bytes.fromhex(
    "000300010001460046000f1204002d3100000000000000000027100e00000000" + "0000000000000000000000000000000000000000000000000000000000000000" + "00000000000000000000000000000000"
)  # 80B

_BARS_CODE_OFF = 14
_MINUTE_CODE_OFF = 14
_QUOTE_CODE_OFF = 36
_BARS_CATEGORY_OFF = 36
_BARS_COUNT_OFF = 44


def _put_code(frame: bytes, code_off: int, market: int, code: str) -> bytes:
    f = bytearray(frame)
    f[code_off : code_off + 6] = code.encode()
    f[code_off - 2] = market
    return bytes(f)


@dataclass
class Bar:
    date: int
    open: float
    high: float
    low: float
    close: float
    amount: float
    vol: float
    float_share: float


class TdxV2Error(Exception):
    pass


class TdxV2Client:
    """新一代 7709 协议客户端。线程不安全，一连接一用，连接内可连续多请求。"""

    def __init__(self, host: str = _DEFAULT_HOST, port: int = 7709, timeout: float = 6.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None

    # ── 连接管理 ──
    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._send(_LOGIN)
        self._recv_payload()  # 登录应答（203B 载荷）

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    # ── 收发原语 ──
    def _send(self, data: bytes) -> None:
        assert self._sock
        self._sock.sendall(data)

    def _recv_payload(self) -> bytes:
        assert self._sock
        self._sock.settimeout(self.timeout)
        header = b""
        while len(header) < HEADER_LEN:
            chunk = self._sock.recv(HEADER_LEN - len(header))
            if not chunk:
                raise TdxV2Error("连接被服务端关闭")
            header += chunk
        if not header.startswith(MAGIC_RSP):
            raise TdxV2Error(f"响应魔数不匹配: {header[:4].hex()}")
        payload_len = struct.unpack("<H", header[12:14])[0]
        payload = b""
        while len(payload) < payload_len:
            chunk = self._sock.recv(payload_len - len(payload))
            if not chunk:
                raise TdxV2Error("载荷不完整")
            payload += chunk
        return payload

    # ── 业务接口 ──
    def get_bars(
        self, market: int, code: str, count: int = 700, category: int = KLINE_DAY
    ) -> list[Bar]:
        """日K（其余周期的类别字段位未映射，暂只保证日线）。"""
        f = bytearray(_BARS)
        f[_BARS_CATEGORY_OFF : _BARS_CATEGORY_OFF + 2] = struct.pack("<H", category)
        f[_BARS_COUNT_OFF : _BARS_COUNT_OFF + 2] = struct.pack("<H", count)
        self._send(_put_code(bytes(f), _BARS_CODE_OFF, market, code))
        return self._decode_bars(self._recv_payload(), code)

    @staticmethod
    def _decode_bars(payload: bytes, code: str) -> list[Bar]:
        # 载荷（16B 帧头已剥）：[0:2] 市场/填充回显，[2:8] 代码回显；36B 记录流
        # 自 offset 33 起；尾部 120B 为 GBK 名称区。
        if payload[2:8] != code.encode():
            raise TdxV2Error(f"日K响应代码回显不匹配: {payload[2:8]!r} != {code}")
        bars: list[Bar] = []
        pos = 33
        end = len(payload) - 120
        while pos + 36 <= end:
            rec = payload[pos : pos + 36]
            date, _z, o, h, l, c, amount, vol = struct.unpack("<I7f", rec[:32])
            (share,) = struct.unpack("<f", rec[32:36])
            bars.append(Bar(int(date), o, h, l, c, amount, float(vol), share))
            pos += 36
        return bars

    def get_quote(self, market: int, code: str) -> bytes:
        """实时快照原始载荷（字段映射随行情时段校准，盘前多为零填充）。"""
        self._send(_put_code(_QUOTE, _QUOTE_CODE_OFF, market, code))
        return self._recv_payload()

    def get_minute_time_data(self, market: int, code: str) -> bytes:
        """当日分时原始载荷（需先登录）。"""
        self._send(_put_code(_MINUTE, _MINUTE_CODE_OFF, market, code))
        return self._recv_payload()

    def get_market_snapshot(self) -> bytes:
        """市场快照原始载荷（00 0d）。"""
        self._send(_SNAPSHOT)
        return self._recv_payload()

    @staticmethod
    def decode_gbk_name(bars_payload: bytes) -> str:
        """从日K载荷尾部 120B 提取 GBK 证券名称。"""
        tail = bars_payload[-120:-88]
        return tail.split(b"\x00")[0].decode("gbk", errors="replace")
