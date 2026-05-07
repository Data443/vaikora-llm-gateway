"""Core types shared across gateway modules."""

from enum import Enum


class Decision(str, Enum):
    """Gateway decision types."""
    ALLOW = "ALLOW"
    ALLOW_LOG = "ALLOW_LOG"
    CONSTRAIN = "CONSTRAIN"
    BLOCK = "BLOCK"
    ERROR = "ERROR"
