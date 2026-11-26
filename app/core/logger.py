"""
OmniFetch Diagnostic Logging Subsystem
Configures rotating file handler at logs/omnifetch.log and console output.
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_DIR = Path(r"C:\Users\shrey\Desktop\OmniFetch\logs")
_LOG_FILE = _LOG_DIR / "omnifetch.log"
_LOGGER_INITIALIZED = False

def init_logging():
    global _LOGGER_INITIALIZED
    if _LOGGER_INITIALIZED:
        return

    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger("omnifetch")
    root_logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 1. Rotating File Handler (5 MB max, 3 backups)
    try:
        file_handler = RotatingFileHandler(
            str(_LOG_FILE),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Failed to setup file logger: {e}", file=sys.stderr)

    # 2. Console Handler (INFO level)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    _LOGGER_INITIALIZED = True
    root_logger.info("OmniFetch logging system initialized.")

def get_logger(name: str) -> logging.Logger:
    if not _LOGGER_INITIALIZED:
        init_logging()
    return logging.getLogger(f"omnifetch.{name}")
