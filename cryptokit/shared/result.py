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
