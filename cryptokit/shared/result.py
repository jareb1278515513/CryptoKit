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
        """指示操作是否成功。"""
        return self.code == StatusCode.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        """转换为可序列化字典。

        Returns:
            dict[str, Any]: 结果字典。
        """
        return {
            "code": int(self.code),
            "message": self.message,
            "data": self.data,
        }

    @classmethod
    def success(cls, data: Any = None, message: str = "成功") -> "OperationResult":
        """构造成功结果。

        Args:
            data: 返回数据。
            message: 返回消息。

        Returns:
            OperationResult: 成功结果对象。
        """
        return cls(code=StatusCode.SUCCESS, message=message, data=data)

    @classmethod
    def failure(
        cls,
        code: StatusCode,
        message: str,
        data: Any = None,
    ) -> "OperationResult":
        """构造失败结果。

        Args:
            code: 错误状态码。
            message: 错误消息。
            data: 附加数据。

        Returns:
            OperationResult: 失败结果对象。
        """
        return cls(code=code, message=message, data=data)
