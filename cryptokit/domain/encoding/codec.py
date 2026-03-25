"""Encoding helpers for Base64 and UTF-8 conversions."""

from __future__ import annotations

import base64


class EncodingError(ValueError):
    """Raised when an encoding operation fails."""


def utf8_encode(text: str) -> bytes:
    if not isinstance(text, str):
        raise EncodingError("text must be str")
    return text.encode("utf-8")


def utf8_decode(raw: bytes) -> str:
    try:
        return bytes(raw).decode("utf-8")
    except (TypeError, UnicodeDecodeError) as exc:
        raise EncodingError("invalid UTF-8 bytes") from exc


def base64_encode(raw: bytes) -> str:
    try:
        return base64.b64encode(bytes(raw)).decode("ascii")
    except TypeError as exc:
        raise EncodingError("input must be bytes-like") from exc


def base64_decode(payload: str) -> bytes:
    if not isinstance(payload, str):
        raise EncodingError("payload must be str")
    try:
        return base64.b64decode(payload.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise EncodingError("invalid Base64 string") from exc
