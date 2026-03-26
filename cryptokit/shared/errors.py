"""共享错误类型与状态码定义。"""

from enum import IntEnum


class StatusCode(IntEnum):
    """统一业务状态码枚举。"""

    SUCCESS = 200
    INVALID_INPUT = 400
    INVALID_KEY_SIZE = 401
    UNSUPPORTED_MODE = 402
    CRYPTO_ERROR = 500
    ENCODING_ERROR = 501


class CryptoKitError(Exception):
    """项目级异常基类。"""
