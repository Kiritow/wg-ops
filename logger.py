import logging

def get_logger(name=None):
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(funcName)s: %(message)s"))
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)
    return logger
