# backend/app/logger.py

import logging
import os
from datetime import datetime

def get_logger(name: str, log_file: str = None) -> logging.Logger:
    """
    Returns a configured logger instance.
    Logs to both console and file if log_file is provided.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # always log to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # log to file if specified
    if log_file:
        os.makedirs("logs", exist_ok=True)
        file_handler = logging.FileHandler(f"logs/{log_file}")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
