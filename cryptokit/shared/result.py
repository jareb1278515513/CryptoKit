"""Unified result object for API and CLI."""

from dataclasses import dataclass
from typing import Any

from .errors import StatusCode


@dataclass(slots=True)
class OperationResult:
    """Return payload with status metadata."""

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
    def success(cls, data: Any = None, message: str = "ok") -> "OperationResult":
        return cls(code=StatusCode.SUCCESS, message=message, data=data)

    @classmethod
    def failure(
        cls,
        code: StatusCode,
        message: str,
        data: Any = None,
    ) -> "OperationResult":
        return cls(code=code, message=message, data=data)
