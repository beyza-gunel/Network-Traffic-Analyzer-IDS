import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


_LOGGER_NAME = (
    "network_traffic_analyzer"
)

_MAX_LOG_BYTES = (
    2
    * 1024
    * 1024
)

_BACKUP_COUNT = 3


def _log_directory():
    directory = (
        Path.home()
        / ".network_traffic_analyzer"
        / "logs"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def get_logger():
    logger = logging.getLogger(
        _LOGGER_NAME
    )

    if logger.handlers:
        return logger

    logger.setLevel(
        logging.INFO
    )

    log_file = (
        _log_directory()
        / "application.log"
    )

    handler = RotatingFileHandler(
        log_file,
        maxBytes=_MAX_LOG_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )

    handler.setFormatter(
        formatter
    )

    logger.addHandler(
        handler
    )

    logger.propagate = False

    return logger


def safe_file_label(
    file_path,
):
    try:
        return Path(
            file_path
        ).name
    except Exception:
        return "<unknown>"
