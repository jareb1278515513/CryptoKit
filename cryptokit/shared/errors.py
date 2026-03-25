"""Shared error types and status codes."""

from enum import IntEnum


class StatusCode(IntEnum):
    SUCCESS = 200
    INVALID_INPUT = 400
    INVALID_KEY_SIZE = 401
    UNSUPPORTED_MODE = 402
    CRYPTO_ERROR = 500
    ENCODING_ERROR = 501


class CryptoKitError(Exception):
    """Base exception for all project-level errors."""
