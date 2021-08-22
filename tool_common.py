# -*- coding: utf-8 -*-
import logging
import json
import traceback
import base64
import hashlib


# Constants
WGOP_USPEEDER_S_PBEGIN = 27100
WGOP_USPEEDER_C_PBEGIN = 28100
WGOP_LB_PBEGIN = 29000
WGOP_UC_PBEGIN = 29100

class SimpleLogger(object):
    def __init__(self, name=None, filename=None, fileonly=False,
                 level=logging.INFO,
                 default_encoding='utf-8',
                 log_format="%(asctime)s @%(module)s [%(levelname)s] %(funcName)s: %(message)s"):
        if name is None:
            name = __name__

        if not filename and fileonly:
            raise Exception("FileOnly=True but no filename provided.")

        self.logger = logging.getLogger(name)
        if not getattr(self.logger, "_is_configured", None):
            formatter = logging.Formatter(log_format)
            if not fileonly:
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(formatter)
                self.logger.addHandler(console_handler)
            if filename is not None:
                file_handler = logging.FileHandler(filename, encoding=default_encoding)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            self.logger.setLevel(level)
            setattr(self.logger, "_is_configured", True)

    # Just acts as a logger
    def __getattr__(self, name):
        return getattr(self.logger, name)


logger = SimpleLogger()


def load_config(filename=None):
    config_filename = filename or "local/config.json"
    try:
        with open(config_filename) as f:
            return json.loads(f.read())
    except Exception:
        logger.error("Unable to load config: {}".format(traceback.format_exc()))
        return {}


def save_config(config, filename=None):
    config_filename = filename or "local/config.json"
    content = json.dumps(config, ensure_ascii=False, default=str, indent=2)
    try:
        with open(config_filename, "w", encoding='utf-8') as f:
            f.write(content)
    except Exception:
        logger.error("Unable to save config: {}".format(traceback.format_exc()))
        logger.info("Config:\n{}".format(content))


def json_to_base64(content):
    return base64.b64encode(json.dumps(content, ensure_ascii=False).encode('utf-8')).decode('utf-8')


def base64_to_json(content):
    return json.loads(base64.b64decode(content).decode('utf-8'))


def get_sha256(content):
    return hashlib.sha256(content).hexdigest()
