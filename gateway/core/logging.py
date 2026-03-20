"""Logging configuration for the gateway."""

import sys
from loguru import logger


def configure_logging(level: str = "INFO") -> None:
    """Configure loguru logging output."""
    logger.remove()
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=level,
    )
