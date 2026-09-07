import logging
import sys
from typing import Optional
from patchstack.config import LoggingConfig


class StructuredLogger:
    """
    Provides a configured logging instance with custom formatting and file/console handlers.
    """
    _logger: Optional[logging.Logger] = None

    @classmethod
    def get_logger(cls, name: str = "patchstack", config: Optional[LoggingConfig] = None) -> logging.Logger:
        if cls._logger and not config:
            return cls._logger

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()

        log_level = getattr(logging, (config.level if config else "INFO").upper(), logging.INFO)

        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File Handler if configured
        if config and config.file_path:
            try:
                file_handler = logging.FileHandler(config.file_path, mode="a", encoding="utf-8")
                file_handler.setLevel(logging.DEBUG)
                file_formatter = logging.Formatter(
                    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
                )
                file_handler.setFormatter(file_formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                console_handler.setFormatter(console_formatter)
                logger.warning(f"Could not initialize file logger at {config.file_path}: {e}")

        cls._logger = logger
        return logger
