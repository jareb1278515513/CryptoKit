"""共享类型别名定义。"""

from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]
"""可视为字节序列的输入类型。"""
