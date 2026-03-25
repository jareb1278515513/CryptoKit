"""Base64 与 UTF-8 编解码工具。"""

from __future__ import annotations

import base64


class EncodingError(ValueError):
    """编码/解码失败时抛出。"""


def utf8_encode(text: str) -> bytes:
    if not isinstance(text, str):
        raise EncodingError("文本输入必须是字符串")
    return text.encode("utf-8")


def utf8_decode(raw: bytes) -> str:
    try:
        return bytes(raw).decode("utf-8")
    except (TypeError, UnicodeDecodeError) as exc:
        raise EncodingError("UTF-8 字节序列无效") from exc


def base64_encode(raw: bytes) -> str:
    try:
        return base64.b64encode(bytes(raw)).decode("ascii")
    except TypeError as exc:
        raise EncodingError("输入必须是 bytes 类型") from exc


def base64_decode(payload: str) -> bytes:
    if not isinstance(payload, str):
        raise EncodingError("输入内容必须是字符串")
    try:
        return base64.b64decode(payload.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise EncodingError("Base64 字符串无效") from exc
