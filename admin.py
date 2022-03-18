import os
import time
import sys
import gzip
import json
import subprocess
import traceback
import hashlib
from prettytable import PrettyTable
from libwgopparser import Parser


def get_sha256(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()


def direct_parse(raw_output):
    wg_prikey = raw_output[0][0]
    wg_pubkey = raw_output[0][1]
    wg_listen_port = int(raw_output[0][2])
    wg_fwmark = 0 if raw_output[0][3] == "off" else int(raw_output[0][3], 16)

    wg_peers = {}
    for line in raw_output[1:]:
        wg_peers[line[0]] = {
            "preshared_key": "" if line[1] == "(none)" else line[1],
            "endpoint": "" if line[2] == "(none)" else line[2],
            "allowed": "" if line[3] == "(none)" else line[3],
            "last_handshake": int(line[4]),
            "rx_bytes": int(line[5]),
            "tx_bytes": int(line[6]),
            "keepalive": 0 if line[7] == "off" else int(line[7]),
        }

    return {
        "private_key": wg_prikey,
        "public_key": wg_pubkey,
        "listen_port": wg_listen_port,
        "fwmark": wg_fwmark,
        "peers": wg_peers,
    }


def direct_dump(interface_name):
    raw_output = subprocess.check_output(["wg", "show", interface_name, "dump"]).decode().strip().split('\n')
    if not raw_output:
        return
    raw_output = [line.split('\t') for line in raw_output]

    return direct_parse(raw_output)


def direct_dump_all():
    raw_output = subprocess.check_output(["wg", "show", "all", "dump"]).decode().strip().split('\n')
    if not raw_output:
        return
    raw_output = [line.split('\t') for line in raw_output]

    raw_lines = {}
    for line in raw_output:
        interface_name = line[0]
        if interface_name not in raw_lines:
            raw_lines[interface_name] = [line[1:]]
        else:
            raw_lines[interface_name].append(line[1:])

    return {interface_name: direct_parse(raw_lines[interface_name]) for interface_name in raw_lines}


class Config:
    def __init__(self, filepath=None):
        self.path_config = filepath or ".local.storage.dat"
        self.config = {}
        self.last_load_hash = ''
        self.ensure_load()

    def _load_config(self):
        with open(self.path_config, 'rb') as f:
            raw_config = f.read()
            loaded_config = json.loads(gzip.decompress(raw_config))
            return loaded_config, get_sha256(raw_config)

    def load(self):
        print('Loading config from {}...'.format(self.path_config))
        self.config, self.last_load_hash = self._load_config()

    def save(self):
        print('Saving config to {}...'.format(self.path_config))

        saved_config = json.dumps(self.config, ensure_ascii=False)
        try:
            if self.last_load_hash:
                _, disk_hash = self._load_config()
                if disk_hash != self.last_load_hash:
                    print('[WARN] file might have been changed/modified out of wg-op-admin.')

            with open(self.path_config, 'wb') as f:
                raw_config = gzip.compress(saved_config.encode())
                f.write(raw_config)
                self.last_load_hash = get_sha256(raw_config)
        except Exception:
            print('Unable to save config, content is printed below to avoid data loss.')
            print(saved_config)
            raise

        print('Config saved.')

    def ensure_load(self):
        try:
            self.load()
        except Exception:
            print(traceback.format_exc())
            print('Unable to load config, try create a new one.')
            self.save()

    def _compile(self, interface_name):
        interface_config = self.config[interface_name]

        output = []
        output.append("[Interface]")
        output.append("Address={}".format(interface_config["address"]))
        output.append("PrivateKey={}".format(interface_config["private_key"]))
        if interface_config["listen_port"]:
            output.append("ListenPort={}".format(interface_config["listen_port"]))

        if interface_config["is_enable_dns_reloader"]:
            output.append("#enable-dns-reload")

        for peer_key in interface_config["peers"]:
            peer_info = interface_config["peers"][peer_key]

            output.append("[Peer]")
            output.append("PublicKey={}".format(peer_key))
            output.append("AllowedIPs={}".format(peer_info["allowed"]))
            if peer_info["keepalive"]:
                output.append("PersistentKeepalive={}".format(peer_info["keepalive"]))
            
            if peer_info["endpoint_type"] == "tunnel":
                output.append("#use-tunnel {}".format(peer_info["endpoint"]))
            elif peer_info["endpoint_type"] == "custom":
                output.append("Endpoint={}".format(peer_info["endpoint"]))
        
        return '\n'.join(output)

    def _build(self, interface_name):
        raw_content = self._compile(interface_name)
        wgop_basepath = os.path.dirname(os.path.realpath(sys.argv[0]))
        parser = Parser(wgop_basepath)
        parser.parse(raw_content)
        parser.compile_interface()
        parser.compile_peers()
        parser.compile_final()
        return parser.get_result()

    def ui_create_interface(self, interface_name):
        if interface_name in self.config:
            print('unable to create interface, name `{}` alreay used.'.format(interface_name))
            return

        print('Generating key pairs...')
        wg_private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
        wg_public_key = subprocess.check_output(["wg", "pubkey"], input=wg_private_key.encode()).decode().strip()

        user_input = input('Enter listen port: (random) ')
        if not user_input:
            wg_port = 0
        else:
            wg_port = int(user_input)

        while True:
            user_input = input('Enter LAN IP: ')
            if not user_input:
                continue

            wg_lan_ip = user_input
            break
        
        self.config[interface_name] = {
            "private_key": wg_private_key,
            "public_key": wg_public_key,
            "listen_port": wg_port,
            "address": wg_lan_ip,
            "interface_name": interface_name,
            "peers": {},
            "connectors": {},
            "servers": {},
            "ts_create": int(time.time()),
        }

        self.save()
        self.ui_interface(interface_name)

    def ui_interface(self, interface_name):
        while True:
            print('''----- Editing interface {} -----
[1] Add peer
[2] List peers
[3] Add connector
[4] List connectors
[q] Quit
'''.format(interface_name))

            user_input = input('> '.format(interface_name))
            if not user_input:
                continue
            user_input = user_input.lower().strip()

            if user_input == 'q':
                return

            if user_input == '1':
                self.ui_add_peer(interface_name)

    def ui_add_peer(self, interface_name):
        print('>>> Creating new peer for interface {}'.format(interface_name))
        while True:
            user_input = input("Enter peer public key: ")
            if user_input:
                break
        wg_peer_key = user_input.strip()
        if wg_peer_key in self.config[interface_name]["peers"]:
            print('Peer already exists.')
            return

        while True:
            user_input = input("Enter peer allowed ips: ")
            if user_input:
                break
        wg_peer_allowed = user_input.strip()

        user_input = input("Enter persistent keepalive: (15) ")
        if user_input:
            wg_peer_keepalive = int(user_input)
        else:
            wg_peer_keepalive = 0
        
        connectors_info = self.config[interface_name]["connectors"]
        if connectors_info:
            print("=== Available connectors ===")
            for conn_name in connectors_info:
                print("[{}] {} {}".format(conn_name, connectors_info[conn_name]["type"], connectors_info[conn_name]["remote"]))
        user_input = input('Enter endpoint: (empty) ')
        if not user_input:
            wg_peer_endpoint = ''
            wg_peer_endpoint_type = ''
        elif user_input.strip() in connectors_info:
            wg_peer_endpoint = user_input.strip()
            wg_peer_endpoint_type = 'tunnel'
        else:
            wg_peer_endpoint = user_input.strip()
            wg_peer_endpoint_type = 'custom'

        if wg_peer_endpoint_type == 'custom' and not self.config[interface_name].get('is_enable_dns_reload', False):
            user_input = input('Enable DNS reloader?: (y/N) ')
            if user_input and user_input.lower().strip() == 'y':
                self.config[interface_name]['is_enable_dns_reload'] = True

        self.config[interface_name]["peers"][wg_peer_key] = {
            "allowed": wg_peer_allowed,
            "keepalive": wg_peer_keepalive,
            "endpoint": wg_peer_endpoint,
            "endpoint_type": wg_peer_endpoint_type,
        }

        self.save()

    def _ui_show_single(self, interface_name, info):
        print('\ninterface: {}\n  public key: {}\n  listening port: {}'.format(interface_name, info['public_key'], info['listen_port']))
        if info['fwmark']:
            print('  fwmark: {} ({})'.format(hex(info['fwmark']), info['fwmark']))

        pt = PrettyTable(["Name", "AllowedIPs", "Endpoint", "Last Handshake", "Received", "Sent", "Keepalive"])
        for peer_key, peer_info in info['peers'].items():
            pt.add_row([peer_key, peer_info['allowed'], peer_info['endpoint'], int(time.time()) - peer_info['last_handshake'] if peer_info['last_handshake'] else "", peer_info['rx_bytes'], peer_info['tx_bytes'], peer_info['keepalive']])

        print(pt.get_string())

    def ui_show_status(self, interface_name):
        if interface_name:
            info = direct_dump(interface_name)
            self._ui_show_single(interface_name, info)
        else:
            info = direct_dump_all()
            for name in info:
                self._ui_show_single(name, info[name])


if __name__ == "__main__":
    c = Config()

    if len(sys.argv) < 2:
        print('Commands: new, list, edit, del, up/start, down/stop, enable, disable, status')
        exit(1)

    if sys.argv[1] == "new":
        if len(sys.argv) < 3:
            print('Syntax: new <interface>')
            exit(1)
        
        wg_name = sys.argv[2]
        c.ui_create_interface(wg_name)

    elif sys.argv[1] == "status":
        if len(sys.argv) < 3:
            c.ui_show_status(None)
        else:
            wg_name = sys.argv[2]
            c.ui_show_status(wg_name)
