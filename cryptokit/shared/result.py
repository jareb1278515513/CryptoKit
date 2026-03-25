"""API 与 CLI 统一返回结构。"""

from dataclasses import dataclass
from typing import Any

from .errors import StatusCode


@dataclass(slots=True)
class OperationResult:
    """包含状态码、消息与数据载荷。"""

    code: StatusCode
    message: str
    data: Any = None

    @property
    def ok(self) -> bool:
        return self.code == StatusCode.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": int(self.code),
            "message": self.message,
            "data": self.data,
        }

    @classmethod
    def success(cls, data: Any = None, message: str = "成功") -> "OperationResult":
        return cls(code=StatusCode.SUCCESS, message=message, data=data)

    @classmethod
    def failure(
        cls,
        code: StatusCode,
        message: str,
        data: Any = None,
    ) -> "OperationResult":
        return cls(code=code, message=message, data=data)
