# -*- coding: utf-8 -*-
import logging
import json
import traceback
import base64
import hashlib
import random
import string


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
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def get_randpass(length):
    return ''.join(random.choices(string.ascii_uppercase, k=2) + random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=length - 2))


def get_quick_config(config, server_public_ip):
    if config["ip"].endswith(".1"):
        suggest_allowed = "{}.0/24".format('.'.join(config["ip"].split('.')[:-1]))
    else:
        suggest_allowed = config["ip"]

    quicks = []

    for server_info in config["udp2raw"]["server"]:
        speeder_info = server_info["speeder"]

        quick_config = {
            "pubkey": config["pubkey"],
            "allowed": suggest_allowed,
            "remote": "{}:{}".format(server_public_ip, server_info["port"]),
            "password": server_info["password"],
            "ratio": speeder_info["ratio"] if speeder_info else None
        }

        quicks.append({
            "port": server_info["port"],
            "qcs": "#QCS#{}".format(json_to_base64(quick_config))
        })

    return quicks


class UConfigController:
    next_port_speeder_server = WGOP_USPEEDER_S_PBEGIN
    next_port_speeder_client = WGOP_USPEEDER_C_PBEGIN
    next_port_balancer = WGOP_LB_PBEGIN
    next_port_client = WGOP_UC_PBEGIN
    udp2raw_config = {
        "server": [],
        "client": []
    }

    def add_server(self, port_required, password, speeder_info):
        self.udp2raw_config["server"].append({
            "port": port_required,
            "password": get_sha256(password),
            "speeder": speeder_info
        })

    def add_client(self, remote, password, port, speeder_info, demuxer_info, no_hash=False):
        if port is None:
            port = self.next_port_client
            if demuxer_info:
                self.next_port_client += demuxer_info["size"]
            else:
                self.next_port_client += 1

        self.udp2raw_config["client"].append({
            "remote": remote,
            "password": password if no_hash else get_sha256(password),
            "port": port,
            "speeder": speeder_info,
            "demuxer": demuxer_info
        })

    def new_server_speeder(self, port, ratio):
        if port is None:
            port = self.next_port_speeder_server
            self.next_port_speeder_server += 1

        return {
            "port": port,
            "ratio": ratio
        }

    def new_client_speeder(self, port, ratio):
        if port is None:
            port = self.next_port_speeder_client
            self.next_port_speeder_client += 1

        return {
            "port": port,
            "ratio": ratio
        }

    def new_demuxer(self, port, size):
        if port is None:
            port = self.next_port_balancer
            self.next_port_balancer += 1

        return {
            "port": port,
            "size": size
        }
