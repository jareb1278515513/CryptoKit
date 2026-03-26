"""Base64 与 UTF-8 编解码工具。"""

from __future__ import annotations

import base64


class EncodingError(ValueError):
    """编码/解码失败时抛出。"""


def utf8_encode(text: str) -> bytes:
    """将字符串编码为 UTF-8 字节串。

    Args:
        text: 待编码文本。

    Returns:
        bytes: UTF-8 编码结果。

    Raises:
        EncodingError: 输入不是字符串时抛出。
    """
    if not isinstance(text, str):
        raise EncodingError("文本输入必须是字符串")
    return text.encode("utf-8")


def utf8_decode(raw: bytes) -> str:
    """将 UTF-8 字节串解码为字符串。

    Args:
        raw: 待解码字节串。

    Returns:
        str: 解码后的文本。

    Raises:
        EncodingError: 输入不是合法 UTF-8 字节串时抛出。
    """
    try:
        return bytes(raw).decode("utf-8")
    except (TypeError, UnicodeDecodeError) as exc:
        raise EncodingError("UTF-8 字节序列无效") from exc


def base64_encode(raw: bytes) -> str:
    """将字节串编码为 Base64 字符串。

    Args:
        raw: 待编码字节串。

    Returns:
        str: Base64 编码文本。

    Raises:
        EncodingError: 输入不是字节序列时抛出。
    """
    try:
        return base64.b64encode(bytes(raw)).decode("ascii")
    except TypeError as exc:
        raise EncodingError("输入必须是 bytes 类型") from exc


def base64_decode(payload: str) -> bytes:
    """将 Base64 字符串解码为字节串。

    Args:
        payload: Base64 文本。

    Returns:
        bytes: 解码后的字节串。

    Raises:
        EncodingError: 输入不是合法 Base64 字符串时抛出。
    """
    if not isinstance(payload, str):
        raise EncodingError("输入内容必须是字符串")
    try:
        return base64.b64decode(payload.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise EncodingError("Base64 字符串无效") from exc
