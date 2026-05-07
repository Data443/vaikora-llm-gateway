"""Logging configuration for the gateway."""

import json
import sys
from loguru import logger


def _json_sink(message) -> None:
    """Serialize loguru record as a single JSON line to stdout."""
    record = message.record
    payload = {
        "timestamp": record["time"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "level": record["level"].name,
        "logger": record["name"],
        "function": record["function"],
        "line": record["line"],
        "message": record["message"],
    }
    if record["exception"] is not None:
        payload["exception"] = str(record["exception"])
    sys.stdout.write(json.dumps(payload, default=str) + "\n")
    sys.stdout.flush()


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    """Configure loguru logging output.

    Args:
        level: Minimum log level.
        fmt: 'text' for human-readable, 'json' for structured JSON lines.
    """
    logger.remove()
    if fmt.lower() == "json":
        logger.add(_json_sink, level=level, colorize=False)
    else:
        logger.add(
            sys.stdout,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
                "<level>{message}</level>"
            ),
            level=level,
        )
