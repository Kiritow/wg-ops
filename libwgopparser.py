import os
import copy
import sys
import time
import uuid
import json
import base64
import traceback
import subprocess
from hashlib import sha256

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def errprint(msg):
    sys.stderr.write("{}\n".format(msg))


def get_subject_name_from_cert(cert_path):
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except Exception:
        errprint(traceback.format_exc())
        return ""


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def get_pem_from_rsa_keypair(private_key, public_key):
    if private_key:
        pripem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()).decode()
    else:
        pripem = None

    if public_key:
        pubpem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    else:
        pubpem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    return pripem, pubpem


def get_rsa_keypair_from_private_pem(private_pem):
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    public_key = private_key.public_key()
    return private_key, public_key


def get_rsa_pubkey_from_public_pem(public_pem):
    public_key = serialization.load_pem_public_key(public_pem.encode())
    return public_key


def rsa_sign_base64(private_key, bytes_data):
    signature = private_key.sign(bytes_data, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ), hashes.SHA256())

    return base64.b64encode(signature).decode()


def rsa_encrypt_base64(public_key, bytes_data):
    return base64.b64encode(public_key.encrypt(bytes_data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))).decode()


def rsa_decrypt_base64(private_key, str_data):
    return private_key.decrypt(base64.b64decode(str_data), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))


class Parser:
    def __init__(self, wgop_basepath):
        # paths
        self._path_base = wgop_basepath
        self.path_get_gateway = os.path.join(wgop_basepath, 'tools/get-gateway.py')
        self.path_get_ip = os.path.join(wgop_basepath, 'tools/get-ip.py')
        self.path_get_lan_ip = os.path.join(wgop_basepath, 'tools/get-lan-ip.py')
        self.path_reload_dns = os.path.join(wgop_basepath, 'tools/reload-dns.py')
        self.path_collect_metrics = os.path.join(wgop_basepath, 'tools/collect-metrics.py')
        self.path_bin_dir = os.path.join(wgop_basepath, 'bin')
        self.path_app_dir = os.path.join(wgop_basepath, 'app')
        self.path_bin_mux = os.path.join(wgop_basepath, 'bin/mux')
        self.path_bin_udp2raw = os.path.join(wgop_basepath, 'bin/udp2raw_amd64')
        self.path_bin_gost = os.path.join(wgop_basepath, 'bin/gost')
        self.path_bin_trojan = os.path.join(wgop_basepath, 'bin/trojan-go')

        # opts
        self.opt_source_path = ''
        self.opt_allow_modify = False
        self.opt_use_tmux = False
        self.opt_use_systemd = False

        # input parts
        self.input_interface = []
        self.input_peer = []

        # output
        self.result_interface = []
        self.result_postup = []
        self.result_postdown = []
        self.result_peers = []

        # container related output
        self.result_container_prebootstrap = []
        self.result_container_postbootstrap = []

        # flags
        self.flag_is_route_forward = False
        self.flag_is_route_lookup = False
        self.flag_container_must_host = False
        self.flag_require_registry = False
        self.flag_enable_dns_reload = False
        self.flag_require_systemd_clean = False
        self.flag_require_tmpfile_clean = False
        self.flag_has_open_tmux = False

        # vars
        self.wg_name = '%i'
        self.wg_port = 0
        self.wg_mtu = 0
        self.wg_pubkey = ''
        self.wg_hash = ''
        self.registry_domain = ''
        self.registry_client_name = ''
        self.local_private_key = None
        self.local_public_key = None
        self.local_autogen_nextport = 29100
        self.pending_accepts = []
        self.tunnel_local_endpoint = {}
        self.tunnel_server_reports = {}
        self.lookup_table = ''
        self.container_expose_port = []
        self.container_bootstrap = []
        self.podman_user = ''
        self.systemd_user = ''

    def get_container_network_name(self):
        if self.flag_container_must_host:
            return "host"
        else:
            return "wgop-net-{}".format(self.wg_name)

    def get_container_name(self):
        return "wgop-runner-{}".format(self.wg_name)

    def get_podman_cmd_with(self, command):
        if self.podman_user:
            return "su - {} -c '{}'".format(self.podman_user, command)
        else:
            return command

    def get_systemd_run_cmd_with(self, command):
        if self.systemd_user:
            return command.replace('systemd-run', 'systemd-run --property User={}'.format(self.systemd_user), 1)
        else:
            return command

    def get_metrics_db_filepath(self):
        return os.path.join(self._path_base, 'local/{}.db'.format(self.wg_name))

    def new_systemd_task_name(self, task_type='general'):
        self.flag_require_systemd_clean = True
        return "wg-ops-task-{}-{}-{}".format(self.wg_name, task_type, str(uuid.uuid4()))

    def new_tmp_filepath(self, suffix=None):
        self.flag_require_tmpfile_clean = True
        return "/tmp/wg-ops-tmpfile-{}-{}{}".format(self.wg_name, str(uuid.uuid4()), suffix if suffix else "")

    def add_write_tmpfile_bytes(self, data_bytes, suffix=None):
        raw_code_str = base64.b64encode(data_bytes).decode()
        raw_parts = []

        while len(raw_code_str) > 1024:
            raw_parts.append(raw_code_str[:1024])
            raw_code_str = raw_code_str[1024:]

        if raw_code_str:
            raw_parts.append(raw_code_str)

        temp_data_path = self.new_tmp_filepath('.data')
        temp_output_path = self.new_tmp_filepath(suffix)

        for this_line in raw_parts:
            self.result_postup.append('echo {} >> {}'.format(this_line, temp_data_path))
        self.result_postup.append('base64 -d {} > {}'.format(temp_data_path, temp_output_path))
        
        return temp_output_path

    def registry_resolve(self, client_name):
        if not self.registry_domain:
            errprint('[ERROR] Cannot query from registry, domain not specified')
            exit(1)
        if not self.registry_client_name:
            errprint('[ERROR] No registry client name found.')
            exit(1)

        errprint('[REGISTRY] Resolving client {} from registry ({})...'.format(client_name, self.registry_domain))
        try:
            res = requests.get('{}/query'.format(self.registry_domain), params={
                "name": client_name,
            })
            res = res.json()
            errprint('[REGISTRY-SERVER] {}'.format(res['message']))

            if res['code'] < 0:
                return {}

            remote_result = res['data']
            remote_peers = remote_result['peers']
            if self.registry_client_name not in remote_peers:
                errprint('[REGISTRY-REMOTE] This client ({}) is not accepted by {}'.format(self.registry_client_name, client_name))
                return {}

            remote_config = rsa_decrypt_base64(self.local_private_key, remote_peers[self.registry_client_name])
            remote_config = json.loads(remote_config)

            remote_peers[self.registry_client_name] = remote_config

            return remote_result
        except Exception:
            errprint(traceback.format_exc())
            errprint('[REGISTRY] Exception happened during registry client resolve')
            return {}
    
    def registry_query(self, client_name):
        if not self.registry_domain:
            errprint('[ERROR] Cannot query from registry, domain not specified')
            exit(1)
        if not self.registry_client_name:
            errprint('[ERROR] No registry client name found.')
            exit(1)
        
        errprint('[REGISTRY] Querying client {}...'.format(client_name))
        try:
            res = requests.get('{}/query'.format(self.registry_domain), params={
                "name": client_name,
            })
            res = res.json()
            errprint('[REGISTRY-SERVER] {}'.format(res['message']))

            if res['code'] < 0:
                return {}

            remote_result = res['data']
            return remote_result
        except Exception:
            errprint(traceback.format_exc())
            errprint('[REGISTRY] Exception happened during registry client query')
            return {}

    def registry_upload(self, content):
        if not self.registry_domain:
            errprint('[ERROR] Cannot query from registry, domain not specified')
            exit(1)
        if not self.registry_client_name:
            errprint('[ERROR] No registry client name found.')
            exit(1)

        errprint('[REGISTRY] Registering this client ({}) with registry ({})...'.format(self.registry_client_name, self.registry_domain))
        try:
            res = requests.post('{}/register'.format(self.registry_domain), json=content)
            res = res.json()

            errprint('[REGISTRY-SERVER] {}'.format(res['message']))
            if res['code'] < 0:
                return False
            else:
                return True
        except Exception:
            errprint(traceback.format_exc())
            errprint('[REGISTRY] Exception happened during registry register')
            return False

    def registry_ensure(self, peers=None):
        _, public_pem = get_pem_from_rsa_keypair(None, self.local_public_key)
        can_ensure = self.registry_upload({
            "name": self.registry_client_name,
            "pubkey": public_pem,
            "wgkey": self.wg_pubkey,
            "peers": peers or {},
            "sig": rsa_sign_base64(self.local_private_key, self.wg_pubkey.encode())
        })
        if not can_ensure:
            errprint('[ERROR] registry ensure failed, please check your network.')
            exit(1)

    def add_expose(self, expose_port, mode='udp'):
        self.container_expose_port.append({
            "port": int(expose_port),
            "mode": mode,
        })

    def append_input_peer_clientside(self, peer_wgkey, allowed_ip, tunnel_name):
        this_peer = []
        this_peer.append("PublicKey = {}".format(peer_wgkey))
        this_peer.append("AllowedIPs = {}".format(allowed_ip))
        this_peer.append("PersistentKeepalive = 5")
        this_peer.append("#use-tunnel {}".format(tunnel_name))
        self.input_peer.append(this_peer)

    def append_input_peer_serverside(self, peer_wgkey, allowed_ip):
        this_peer = []
        this_peer.append("PublicKey = {}".format(peer_wgkey))
        this_peer.append("AllowedIPs = {}".format(allowed_ip))
        self.input_peer.append(this_peer)

    def _ensure_open_tmux(self):
        if not self.flag_has_open_tmux:
            self.flag_has_open_tmux = True
            self.result_postup.append('''tmux new-session -s tunnel-{} -d 'watch -n 1 --color WG_COLOR_MODE=always wg show {}' '''.format(self.wg_name, self.wg_name))

    def _add_tunnel_local_endpoint(self, tunnel_name, listen_port):
        if self.opt_use_tmux or self.opt_use_systemd:
            self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        elif self.podman_user:
            self.add_expose(listen_port)
            self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        else:
            self.tunnel_local_endpoint[tunnel_name] = "gateway:{}".format(listen_port)

    def add_muxer(self, listen_port, forward_start, forward_size):
        if self.opt_use_tmux:
            self._ensure_open_tmux()
            self.result_postup.append('''tmux new-window -t tunnel-{} -d '{} -l {} -t {} -s {}' '''.format(
                self.wg_name, self.path_bin_mux, listen_port, forward_start, forward_size,
            ))
            return

        if self.opt_use_systemd:
            self.result_postup.append('systemd-run --unit {} --collect --property Restart=always {} -l {} -t {} -s {}'.format(
                self.new_systemd_task_name('muxer'), self.path_bin_mux, listen_port, forward_start, forward_size,
            ))
            return

        self.container_bootstrap.append({
            "type": "mux",
            "listen": int(listen_port),
            "forward": int(forward_start),
            "size": int(forward_size),
        })

    def add_gost_server(self, tunnel_name, listen_port):
        self.tunnel_server_reports[tunnel_name] = {
            "type": "gost",
            "listen": int(listen_port),
        }

        if self.opt_use_tmux:
            self._ensure_open_tmux()
            self.result_postup.append('''tmux new-window -t tunnel-{} -d '{} -L=relay+tls://:{}/127.0.0.1:{}' '''.format(
                self.wg_name, self.path_bin_gost, listen_port, self.wg_port,
            ))
            return
        
        if self.opt_use_systemd:
            self.result_postup.append('systemd-run --unit {} --collect --property Restart=always {} -L=relay+tls://:{}/127.0.0.1:{}'.format(
                self.new_systemd_task_name('gost-server'), self.path_bin_gost, listen_port, self.wg_port,
            ))
            return

        self.container_bootstrap.append({
            "type": "gost-server",
            "listen": int(listen_port),
        })

    def add_gost_client_with(self, remote_config, remote_peer_config):
        self.local_autogen_nextport += 1
        tunnel_name = "gen{}{}".format(self.wg_hash[:8], self.local_autogen_nextport)
        self.add_gost_client(tunnel_name, self.local_autogen_nextport, "{}:{}".format(remote_config['ip'], remote_peer_config['listen']))
        self.append_input_peer_clientside(remote_config["wgkey"], remote_peer_config["allowed"], tunnel_name)

    def add_gost_client_mux(self, tunnel_name, mux_size, listen_port, tunnel_remote):
        self._add_tunnel_local_endpoint(tunnel_name, listen_port)

        self.add_muxer(listen_port, listen_port + 1, mux_size)
        for mux_idx in range(mux_size):
            self._do_add_gost_client(listen_port + 1 + mux_idx, tunnel_remote)

    def add_gost_client(self, tunnel_name, listen_port, tunnel_remote):
        self._add_tunnel_local_endpoint(tunnel_name, listen_port)
        self._do_add_gost_client(listen_port, tunnel_remote)

    def _do_add_gost_client(self, listen_port, tunnel_remote):
        if self.opt_use_tmux:
            self._ensure_open_tmux()
            self.result_postup.append('''tmux new -t tunnel-{} -d '{} -L udp://:{} -F relay+tls://{}' '''.format(
                self.wg_name, self.path_bin_gost, listen_port, tunnel_remote,
            ))
            return
        
        if self.opt_use_systemd:
            self.result_postup.append('systemd-run --unit {} --collect --property Restart=always {} -L udp://:{} -F relay+tls://{}'.format(
                self.new_systemd_task_name('gost-client'), self.path_bin_gost, listen_port, tunnel_remote,
            ))
            return

        self.container_bootstrap.append({
            "type": "gost-client",
            "listen": int(listen_port),
            "remote": tunnel_remote,
        })

    def add_udp2raw_server(self, tunnel_name, listen_port, tunnel_password):
        self.tunnel_server_reports[tunnel_name] = {
            "type": "udp2raw",
            "listen": int(listen_port),
            "password": tunnel_password,
        }

        if self.opt_use_tmux or self.opt_use_systemd:
            temp_config_path = self.new_tmp_filepath('.conf')
            self.result_postup.append('''echo -e '-s\\n-l 0.0.0.0:{}\\n-r 127.0.0.1:{}\\n-k {}\\n--raw-mode faketcp\\n-a' > {}'''.format(
                listen_port, self.wg_port, tunnel_password, temp_config_path
            ))

        if self.opt_use_tmux:
            self._ensure_open_tmux()
            self.result_postup.append('''tmux new-window -t tunnel-{} -n win-{} -d '{} --conf-file {}'; sleep 2 '''.format(
                self.wg_name, tunnel_name, self.path_bin_udp2raw, temp_config_path,
            ))
            self.result_postdown.append('''sleep 1; tmux send-keys -t tunnel-{}:win-{} C-c'''.format(self.wg_name, tunnel_name))
            return

        if self.opt_use_systemd:
            self.result_postup.append('systemd-run --unit {} --collect --property Restart=always --property KillSignal=SIGINT {} --conf-file {}; sleep 2'.format(
                self.new_systemd_task_name('udp2raw-server'), self.path_bin_udp2raw, temp_config_path,
            ))
            return

        conf_uuid = str(uuid.uuid4())
        self.container_bootstrap.append({
            "type": "udp2raw-server",
            "listen": int(listen_port),
            "password": tunnel_password,
            "id": conf_uuid,
        })

        ipt_filename_inside = "/root/conf/{}-ipt.conf".format(conf_uuid)
        self.result_container_postbootstrap.append('IPT_COMMANDS=$({}); echo $IPT_COMMANDS; $IPT_COMMANDS'.format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))
        self.result_postdown.append("IPT_COMMANDS=$({}); IPT_COMMANDS=$(echo $IPT_COMMANDS | sed -e 's/-I /-D /g'); echo $IPT_COMMANDS; $IPT_COMMANDS".format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))

    def add_udp2raw_client_with(self, remote_config, remote_peer_config):
        self.local_autogen_nextport += 1
        tunnel_name = "gen{}{}".format(self.wg_hash[:8], self.local_autogen_nextport)
        self.add_udp2raw_client(tunnel_name, self.local_autogen_nextport, remote_peer_config["password"], "{}:{}".format(remote_config['ip'], remote_peer_config['listen']))
        self.append_input_peer_clientside(remote_config["wgkey"], remote_peer_config["allowed"], tunnel_name)

    def add_udp2raw_client_mux(self, tunnel_name, mux_size, listen_port, tunnel_password, remote_addr):
        self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        self.flag_container_must_host = True

        self.add_muxer(listen_port, listen_port+1, mux_size)
        for mux_idx in range(mux_size):
            self._do_add_udp2raw_client(tunnel_name, listen_port + 1 + mux_idx, tunnel_password, remote_addr)

    def add_udp2raw_client(self, tunnel_name, listen_port, tunnel_password, remote_addr):
        self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        self.flag_container_must_host = True

        self._do_add_udp2raw_client(tunnel_name, listen_port, tunnel_password, remote_addr)

    def _do_add_udp2raw_client(self, tunnel_name, listen_port, tunnel_password, remote_addr):
        if self.opt_use_tmux or self.opt_use_systemd:
            temp_config_path = self.new_tmp_filepath('.conf')
            self.result_postup.append('''echo -e '-c\\n-l 127.0.0.1:{}\\n-r {}\\n-k {}\\n--raw-mode faketcp\\n-a' > {}'''.format(
                listen_port, remote_addr, tunnel_password, temp_config_path,
            ))

        if self.opt_use_tmux:
            self._ensure_open_tmux()            
            self.result_postup.append('''tmux new-window -t tunnel-{} -n win-{} -d '{} --conf-file {}'; sleep 2 '''.format(
                self.wg_name, tunnel_name, self.path_bin_udp2raw, temp_config_path,
            ))
            self.result_postdown.append('''sleep 1; tmux send-keys -t tunnel-{}:win-{} C-c'''.format(self.wg_name, tunnel_name))
            return

        if self.opt_use_systemd:
            self.result_postup.append('systemd-run --unit {} --collect --property Restart=always --property KillSignal=SIGINT {} --conf-file {}; sleep 2'.format(
                self.new_systemd_task_name('udp2raw-client'), self.path_bin_udp2raw, temp_config_path,
            ))
            return

        conf_uuid = str(uuid.uuid4())
        self.container_bootstrap.append({
            "type": "udp2raw-client",
            "listen": int(listen_port),
            "password": tunnel_password,
            "remote": remote_addr,
            "id": conf_uuid,
        })

        ipt_filename_inside = "/root/conf/{}-ipt.conf".format(conf_uuid)
        self.result_container_postbootstrap.append('IPT_COMMANDS=$({}); echo $IPT_COMMANDS; $IPT_COMMANDS'.format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))
        self.result_postdown.append("IPT_COMMANDS=$({}); IPT_COMMANDS=$(echo $IPT_COMMANDS | sed -e 's/-I /-D /g'); echo $IPT_COMMANDS; $IPT_COMMANDS".format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))

    def add_trojan_server(self, tunnel_name, listen_port, tunnel_password, ssl_cert_path, ssl_key_path):
        self.tunnel_server_reports[tunnel_name] = {
            "type": "trojan",
            "listen": int(listen_port),
            "password": tunnel_password,
            "target": int(self.wg_port),
            "sni": get_subject_name_from_cert(ssl_cert_path),
        }

        if self.opt_use_tmux or self.opt_use_systemd:
            errprint('[ERROR] Unable to create trojan-go server in tmux or systemd mode. Please use container mode.')
            exit(1)

        cert_uuid = str(uuid.uuid4())
        cert_filepath = "/root/ssl/{}.cert".format(cert_uuid)
        key_filepath = "/root/ssl/{}.key".format(cert_uuid)

        self.result_container_prebootstrap.append(self.get_podman_cmd_with(
            'podman cp {} {}:{}'.format(ssl_cert_path, self.get_container_name(), cert_filepath)
        ))
        self.result_container_prebootstrap.append(self.get_podman_cmd_with(
            'podman cp {} {}:{}'.format(ssl_key_path, self.get_container_name(), key_filepath)
        ))

        self.container_bootstrap.append({
            "type": "trojan-server",
            "listen": int(listen_port),
            "password": tunnel_password,
            "cert": cert_uuid,
        })


    def add_trojan_client_with(self, remote_config, remote_peer_config):
        self.local_autogen_nextport += 1
        tunnel_name = "gen{}{}".format(self.wg_hash[:8], self.local_autogen_nextport)
        self.add_trojan_client(tunnel_name, self.local_autogen_nextport, remote_peer_config["password"],
            "{}:{}".format(remote_config["ip"], remote_peer_config["listen"]), remote_peer_config["target"], ssl_sni=remote_peer_config["sni"])
        self.append_input_peer_clientside(remote_config["wgkey"], remote_peer_config["allowed"], tunnel_name)

    def add_trojan_client_mux(self, tunnel_name, mux_size, listen_port, tunnel_password, remote_addr, target_port, ssl_sni=None):
        self._add_tunnel_local_endpoint(tunnel_name, listen_port)
        self.add_muxer(listen_port, listen_port+1, mux_size)
        for mux_idx in range(mux_size):
            self._do_add_trojan_client(tunnel_name, listen_port + 1 + mux_idx, tunnel_password, remote_addr, target_port, ssl_sni)

    def add_trojan_client(self, tunnel_name, listen_port, tunnel_password, remote_addr, target_port, ssl_sni=None):
        self._add_tunnel_local_endpoint(tunnel_name, listen_port)
        self._do_add_trojan_client(tunnel_name, listen_port, tunnel_password, remote_addr, target_port, ssl_sni)

    def _do_add_trojan_client(self, tunnel_name, listen_port, tunnel_password, remote_addr, target_port, ssl_sni):
        if self.opt_use_tmux or self.opt_use_systemd:
            if ':' in remote_addr:
                remote_parts = remote_addr.split(':')
                remote_host = remote_parts[0]
                remote_port = int(remote_parts[1])
            else:
                remote_host = remote_addr
                remote_port = 443

            troj_config = {
                "run_type": "forward",
                "local_addr": "0.0.0.0",
                "local_port": int(listen_port),
                "remote_addr": remote_host,
                "remote_port": remote_port,
                "target_addr": "127.0.0.1",
                "target_port": target_port,
                "password": [tunnel_password],
                "ssl": {
                    "sni": ssl_sni if ssl_sni else remote_host,
                }
            }

            temp_config_path = self.add_write_tmpfile_bytes(json.dumps(troj_config, ensure_ascii=False).encode(), '.json')

        if self.opt_use_tmux:
            self.result_postup.append('''tmux new-window -t tunnel-{} -d '{} -config {}' '''.format(
                self.wg_name, self.path_bin_trojan, temp_config_path,
            ))
            return

        if self.opt_use_systemd:
            self.result_postup.append('systemd-run --unit {} --collect --property Restart=always {} -config {}'.format(
                self.new_systemd_task_name('trojan-client'), self.path_bin_trojan, temp_config_path,
            ))
            return

        self.container_bootstrap.append({
            "type": "trojan-client",
            "listen": int(listen_port),
            "password": tunnel_password,
            "remote": remote_addr,
            "target": int(target_port),
            "sni": ssl_sni,
        })

    def parse(self, content):
        self.wg_hash = sha256(content.encode()).hexdigest()
        errprint('[INFO] config hash: {}'.format(self.wg_hash))

        # parse input
        input_mode = ''
        current_peer = []
        for line in content.split('\n'):
            # tags to filter out (never enter compile module)
            if line.startswith('#store:key'):
                parts = line.split(' ')[1:]
                private_pem = parts[0]
                private_pem = base64.b64decode(private_pem).decode()

                self.local_private_key, self.local_public_key = get_rsa_keypair_from_private_pem(private_pem)
                errprint('Loaded 1 PEM private key')
                continue

            if line.startswith('[Interface]'):
                input_mode = 'interface'
                continue

            if line.startswith('[Peer]'):
                input_mode = 'peer'
                if current_peer:
                    self.input_peer.append(current_peer)
                    current_peer = []
                continue

            if input_mode == 'interface':
                self.input_interface.append(line)
            elif input_mode == 'peer':
                current_peer.append(line)
            else:
                errprint('[WARN] Unexpected line: {}'.format(line))

        if current_peer:
            self.input_peer.append(current_peer)

    def compile_interface(self):
        self.result_interface.append('[Interface]')

        filtered_input_interface = []
        unresolved_peers = []

        # pre-compile registry-related
        for line in self.input_interface:
            if line.startswith('ListenPort'):
                self.wg_port = int(line.split('=')[1])
            if line.startswith('MTU'):
                self.wg_mtu = int(line.split('=')[1])
            if line.startswith('PrivateKey'):
                wg_private_key = '='.join(line.split('=')[1:]).strip()
                self.wg_pubkey = subprocess.check_output(["wg", "pubkey"], input=wg_private_key.encode()).decode().strip()

            if line.startswith('#registry '):
                parts = line.split(' ')[1:]
                reg_name = parts[0]

                self.registry_domain = "https://{}".format(reg_name)
            elif line.startswith('#registry-insecure'):
                parts = line.split(' ')[1:]
                reg_name = parts[0]

                self.registry_domain = "http://{}".format(reg_name)
                errprint('[WARN] Insecure registry may have potential danger, only use for test purpose.')
            elif line.startswith('#name'):
                parts = line.split(' ')[1:]
                client_name = parts[0]

                self.registry_client_name = client_name
                self.flag_require_registry = True
            elif line.startswith('#connect-to'):
                parts = line.split(' ')[1:]
                target_name = parts[0]

                unresolved_peers.append(target_name)
                self.flag_require_registry = True
            elif line.startswith('#accept-client'):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                client_name = parts[1]
                client_ip = parts[2]
                client_allowed = parts[3]
                peer_allowed = parts[4]

                self.pending_accepts.append({
                    "tunnel": tunnel_name,
                    "client": client_name,
                    "client_ip": client_ip,
                    "allowed": client_allowed,
                    "peer_allowed": peer_allowed,
                })
                self.flag_require_registry = True
            else:
                filtered_input_interface.append(line)

        # registry init
        if self.flag_require_registry:
            if not self.local_private_key:
                errprint('registry required but no existing private key found, generating new...')

                self.local_private_key, self.local_public_key = generate_rsa_keypair()
                private_pem, _ = get_pem_from_rsa_keypair(self.local_private_key, self.local_public_key)

                if self.opt_allow_modify:
                    errprint('[MODIFY] appending to {}...'.format(self.opt_source_path))
                    with open(self.opt_source_path, 'a') as f:
                        f.write('\n#store:key {}\n'.format(base64.b64encode(private_pem.encode()).decode()))
                    errprint('[MODIFY] source file modifed, please re-run to continue.')
                else:
                    errprint('[ERROR] cannot modify source file, please re-run with -i option.')
                exit(1)

            self.registry_ensure()

            # registry fetch connect-to
            for peer_client_name in unresolved_peers:
                errprint('[REGISTRY-RESOLVE] Resolving connect-to {}...'.format(peer_client_name))
                peer_client_config = self.registry_resolve(peer_client_name)
                if not peer_client_config:
                    errprint('[WARN] Unable to resolve client: {}'.format(peer_client_name))
                    continue

                peer_config = peer_client_config["peers"][self.registry_client_name]
                {
                    "udp2raw": self.add_udp2raw_client_with,
                    "gost": self.add_gost_client_with,
                    "trojan": self.add_trojan_client_with,
                }.get(peer_config["type"], lambda x, y: False)(peer_client_config, peer_config)

        # compile interface
        for line in filtered_input_interface:
            if line.startswith('PostUp'):
                self.result_postup.append(','.join(line.split('=')[1:]).strip())
                continue
            if line.startswith('PostDown'):
                self.result_postdown.append(','.join(line.split('=')[1:]).strip())
                continue

            if not line.startswith('#'):
                self.result_interface.append(line)
                continue

            elif line.startswith('#enable-bbr'):
                self.result_postup.append('sysctl net.core.default_qdisc=fq')
                self.result_postup.append('sysctl net.ipv4.tcp_congestion_control=bbr')
            elif line.startswith('#enable-forward'):
                self.result_postup.append('sysctl net.ipv4.ip_forward=1')
            elif line.startswith('#iptables-forward'):
                self.result_postup.append('iptables -A FORWARD -i {} -j ACCEPT'.format(self.wg_name))
                self.result_postdown.append('iptables -D FORWARD -i {} -j ACCEPT'.format(self.wg_name))
            elif line.startswith('#iptables-gateway'):
                self.result_postup.append('iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(self.wg_name))
                self.result_postdown.append('iptables -t nat -D POSTROUTING -o {} -j MASQUERADE'.format(self.wg_name))
            elif line.startswith('#enable-dns-reload'):
                self.flag_enable_dns_reload = True
            elif line.startswith('#enable-collect-metrics'):
                self.result_postup.append('systemd-run --unit {} --collect --timer-property AccuracySec=10 --on-calendar *:*:0/30 /usr/bin/python3 {} {} {}'.format(
                    self.new_systemd_task_name('metrics'), self.path_collect_metrics, self.wg_name, self.get_metrics_db_filepath()
                ))
            elif line.startswith('#route-to'):
                self.flag_is_route_forward = True

                parts = line.split(' ')[1:]
                table_name = parts[0]

                self.result_postup.append('ip route add 0.0.0.0/0 dev {} table {}'.format(self.wg_name, table_name))
                errprint('[WARN] Please ensure custom route table {} exists.'.format(table_name))
            elif line.startswith('#route-from'):
                self.flag_is_route_lookup = True

                parts = line.split(' ')[1:]
                table_name = parts[0]

                self.lookup_table = table_name
                errprint('[WARN] Please ensure custom route table {} exists.'.format(table_name))
            elif line.startswith('#podman-user'):
                parts = line.split(' ')[1:]
                user_name = parts[0]

                if user_name == "root":
                    errprint('[WARN] ignoring root as podman user.')
                else:
                    self.podman_user = user_name
            elif line.startswith('#systemd-user'):
                parts = line.split(' ')[1:]
                user_name = parts[0]

                if user_name == "root":
                    errprint('[WARN] ignoring root as systemd-run user.')
                else:
                    self.systemd_user = user_name
            elif line.startswith('#udp2raw-server'):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = int(parts[1])
                tunnel_passwd = parts[2]

                if self.podman_user:
                    errprint('[Error] udp2raw tunnel need root as podman user, got {}'.format(self.podman_user))
                    exit(1)

                self.add_udp2raw_server(tunnel_name, tunnel_port, tunnel_passwd)
                self.flag_container_must_host = True
            elif line.startswith('#udp2raw-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = int(parts[1])
                tunnel_remote = parts[2]
                tunnel_passwd = parts[3]

                if self.podman_user:
                    errprint('[Error] udp2raw tunnel need root as podman user, got {}'.format(self.podman_user))
                    exit(1)

                self.add_udp2raw_client(tunnel_name, tunnel_port, tunnel_passwd, tunnel_remote)
            elif line.startswith('#udp2raw-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = int(parts[1])
                tunnel_port = int(parts[2])
                tunnel_remote = parts[3]
                tunnel_passwd = parts[4]

                if self.podman_user:
                    errprint('[Error] udp2raw tunnel need root as podman user, got {}'.format(self.podman_user))
                    exit(1)

                self.add_udp2raw_client_mux(tunnel_name, tunnel_mux, tunnel_port + 1 + mux_idx, tunnel_passwd, tunnel_remote)
            elif line.startswith('#gost-server '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = int(parts[1])

                self.add_gost_server(tunnel_name, tunnel_port)
                self.add_expose(tunnel_port, mode='tcp')
            elif line.startswith('#gost-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = int(parts[1])
                tunnel_remote = parts[2]

                self.add_gost_client(tunnel_name, tunnel_port, tunnel_remote)
            elif line.startswith('#gost-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = int(parts[1])
                tunnel_port = int(parts[2])
                tunnel_remote = parts[3]

                self.add_gost_client_mux(tunnel_name, tunnel_mux, tunnel_port, tunnel_remote)
            elif line.startswith('#trojan-server'):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = int(parts[1])
                tunnel_passwd = parts[2]
                tunnel_cert = parts[3]
                tunnel_key = parts[4]

                self.add_trojan_server(tunnel_name, tunnel_port, tunnel_passwd, tunnel_cert, tunnel_key)
                self.add_expose(tunnel_port, mode='tcp')
            elif line.startswith('#trojan-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = int(parts[1])
                tunnel_passwd = parts[2]
                tunnel_remote = parts[3]
                tunnel_target = int(parts[4])

                self.add_trojan_client(tunnel_name, tunnel_port, tunnel_passwd, tunnel_remote, tunnel_target)
            elif line.startswith('#trojan-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = int(parts[1])
                tunnel_port = int(parts[2])
                tunnel_passwd = parts[3]
                tunnel_remote = parts[4]
                tunnel_target = int(parts[5])

                self.tunnel_local_endpoint[tunnel_name] = "gateway:{}".format(tunnel_port)
                self.add_muxer(tunnel_port, tunnel_port+1, tunnel_mux)
                for mux_idx in range(tunnel_mux):
                    self.add_trojan_client(tunnel_port + 1 + mux_idx, tunnel_passwd, tunnel_remote, tunnel_target)

                if self.podman_user:
                    self.add_expose(tunnel_port)
                    self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(tunnel_port)
            else:
                errprint('[WARN] comment or unknown hint: {}'.format(line))

        if not self.wg_mtu and self.container_bootstrap:
            errprint('[WARN] MTU not detected, using suggested mtu value (1280).')
            self.result_interface.append('MTU=1280')

        if self.opt_use_tmux:
            self.result_postdown.append('''sleep 1; tmux kill-session -t tunnel-{}'''.format(self.wg_name))

        if self.opt_use_tmux or self.opt_use_systemd:
            self.container_bootstrap.clear()
            self.result_container_prebootstrap.clear()
            self.result_container_postbootstrap.clear()

        if self.container_bootstrap:
            tmp_filepath = self.add_write_tmpfile_bytes(json.dumps(self.container_bootstrap, ensure_ascii=False).encode(), '.json')
            self.result_container_prebootstrap.append(self.get_podman_cmd_with(
                'podman cp {} {}:/root/conf/bootstrap.json'.format(tmp_filepath, self.get_container_name())
            ))

        if self.result_container_prebootstrap or self.result_container_postbootstrap:
            self.result_postup.append(self.get_podman_cmd_with(
                'podman container exists {} && podman stop {} && podman rm {}; $(exit 0)'.format(self.get_container_name(), self.get_container_name(), self.get_container_name())
            ))

            self.result_postup.append(self.get_podman_cmd_with(
                'podman network exists {} && podman network rm {}; $(exit 0)'.format(self.get_container_network_name(), self.get_container_network_name())
            ))

            if not self.flag_container_must_host:
                self.result_postup.append(self.get_podman_cmd_with(
                    'podman network create {}'.format(self.get_container_network_name())
                ))

            if not self.flag_container_must_host and self.container_expose_port:
                cmd_ports = ["-p {}:{}/{}".format(this_port['port'], this_port['port'], this_port['mode']) for this_port in self.container_expose_port]
                cmd_ports = ' '.join(cmd_ports)
            else:
                cmd_ports = ''

            self.result_postup.append(self.get_podman_cmd_with(
                'podman run --cap-add NET_RAW -v {}:/root/bin -v {}:/root/app {} --name {} --network {} -d wg-ops-runenv'.format(
                    self.path_bin_dir, self.path_app_dir, cmd_ports, self.get_container_name(), self.get_container_network_name())
            ))
            self.result_postup.append(self.get_podman_cmd_with(
                'podman exec {} mkdir -p /root/ssl /root/runner /root/conf'.format(self.get_container_name())
            ))

            if not self.flag_container_must_host and not self.podman_user:
                    self.result_postup.append("CT_IP=$({}); iptables -A FORWARD -d $CT_IP -j ACCEPT; iptables -A INPUT -s $CT_IP -j ACCEPT".format(
                        self.get_podman_cmd_with('/usr/bin/python3 {} {} {}'.format(self.path_get_ip, self.get_container_network_name(), self.get_container_name()))))
                    self.result_postdown.append("CT_IP=$({}); iptables -D FORWARD -d $CT_IP -j ACCEPT; iptables -D INPUT -s $CT_IP -j ACCEPT".format(
                        self.get_podman_cmd_with('/usr/bin/python3 {} {} {}'.format(self.path_get_ip, self.get_container_network_name(), self.get_container_name()))))

            self.result_postdown.append(self.get_podman_cmd_with('podman stop {}'.format(self.get_container_name())))
            self.result_postdown.append(self.get_podman_cmd_with('podman rm {}'.format(self.get_container_name())))

            if not self.flag_container_must_host:
                self.result_postdown.append(self.get_podman_cmd_with('podman network rm {}'.format(self.get_container_network_name())))

            self.result_postup.extend(self.result_container_prebootstrap)

            if self.flag_container_must_host:
                self.result_postup.append(self.get_podman_cmd_with(
                    'podman exec -t -e GATEWAY_IP=127.0.0.1 -e WG_PORT={} {} /usr/bin/python3 /root/app/bootstrap.py'.format(self.wg_port, self.get_container_name())
                ))
            elif self.podman_user:
                self.result_postup.append(self.get_podman_cmd_with(
                    'CT_GATEWAY=$(/usr/bin/python3 {}); podman exec -t -e GATEWAY_IP=$CT_GATEWAY -e WG_PORT={} {} /usr/bin/python3 /root/app/bootstrap.py'.format(
                        self.path_get_lan_ip, self.wg_port, self.get_container_name())
                ))
            else:
                self.result_postup.append(self.get_podman_cmd_with(
                    'CT_GATEWAY=$(/usr/bin/python3 {} {}); podman exec -t -e GATEWAY_IP=$CT_GATEWAY -e WG_PORT={} {} /usr/bin/python3 /root/app/bootstrap.py'.format(
                        self.path_get_gateway, self.get_container_network_name(), self.wg_port, self.get_container_name())
                ))

            self.result_postup.extend(self.result_container_postbootstrap)
        
        # registry fetch accept-client
        if self.flag_require_registry and self.pending_accepts:
            resolved_upload_arr = {}

            for accept_info in self.pending_accepts:
                peer_client_name = accept_info["client"]
                errprint('[REGISTRY-RESOLVE] Resolving accept-client {}...'.format(peer_client_name))
                peer_client_config = self.registry_query(peer_client_name)
                if not peer_client_config:
                    errprint('[WARN] Unable to resolve client: {}'.format(peer_client_name))
                    continue

                self.append_input_peer_serverside(peer_client_config["wgkey"], accept_info["allowed"])

                peer_tunnel_info = copy.copy(self.tunnel_server_reports[accept_info['tunnel']])
                peer_tunnel_info["allowed"] = accept_info["peer_allowed"]

                public_key = get_rsa_pubkey_from_public_pem(peer_client_config["pubkey"])
                resolved_upload_arr[peer_client_name] = rsa_encrypt_base64(public_key, json.dumps(peer_tunnel_info, ensure_ascii=False).encode())

            if resolved_upload_arr:
                self.registry_ensure(peers=resolved_upload_arr)

    def compile_peers(self):
        if self.flag_is_route_forward and len(self.input_peer) > 1:
            errprint('[WARN] route-forward should used with ONLY one peer.')

        for this_peer_idx, this_peer_lines in enumerate(self.input_peer):
            current_pubkey = ''
            current_allowed = ''
            current_endpoint = ''
            if self.flag_is_route_lookup:
                current_lookup = self.lookup_table
            else:
                current_lookup = ''

            # pre-scan
            for line in this_peer_lines:
                if line.startswith('PublicKey'):
                    current_pubkey =  '='.join(line.split('=')[1:]).strip()
                if line.startswith('AllowedIPs'):
                    current_allowed = line.split('=')[1].strip().split(',')
                if line.startswith('Endpoint'):
                    current_endpoint = line.split('=')[1].strip()

            self.result_peers.append('[Peer]')

            # compile peer
            for line in this_peer_lines:
                if not line.startswith('#'):
                    self.result_peers.append(line)
                    continue

                if line.startswith('#use-tunnel'):
                    current_endpoint = ''

                    parts = line.split(' ')[1:]
                    tunnel_name = parts[0]

                    tunnel_addr = self.tunnel_local_endpoint[tunnel_name]
                    if ":" in tunnel_addr:
                        addr_parts = tunnel_addr.split(':')
                        addr_host = addr_parts[0]
                        addr_port = int(addr_parts[1])

                        if addr_host == "gateway":
                            tunnel_addr = ""
                            if self.flag_container_must_host or self.podman_user:
                                self.result_postup.append("wg set {} peer {} endpoint 127.0.0.1:{}".format(
                                    self.wg_name, current_pubkey, addr_port))
                            else:
                                self.result_postup.append("CT_IP=$({}); wg set {} peer {} endpoint $CT_IP:{}".format(
                                    self.get_podman_cmd_with('/usr/bin/python3 {} {} {}'.format(self.path_get_ip, self.get_container_network_name(), self.get_container_name())),
                                    self.wg_name, current_pubkey, addr_port))
                    elif tunnel_addr:
                        tunnel_addr = "127.0.0.1:{}".format(tunnel_addr)

                    if tunnel_addr:
                        self.result_peers.append('Endpoint={}'.format(tunnel_addr))
                elif line.startswith('#route-from'):
                    parts = line.split(' ')[1:]
                    table_name = parts[0]

                    if table_name != self.lookup_table:
                        current_lookup = table_name
                        errprint('[WARN] Please ensure custom route table {} exists.'.format(table_name))
                elif line.startswith('#iptables-gateway'):
                    parts = line.split(' ')[1:]
                    interface_name = parts[0]

                    for ip_cidr in current_allowed:
                        self.result_postup.append('iptables -t nat -A POSTROUTING -s {} -o {} -j MASQUERADE'.format(ip_cidr, interface_name))
                        self.result_postdown.append('iptables -t nat -D POSTROUTING -s {} -o {} -j MASQUERADE'.format(ip_cidr, interface_name))
                else:
                    errprint('[WARN] comment or unknown hint: {}'.format(line))

            if self.flag_enable_dns_reload and current_endpoint:
                self.result_postup.append('systemd-run --unit {} --collect --timer-property AccuracySec=10 --on-calendar *:*:0/30 /usr/bin/python3 {} {} {} {}'.format(
                    self.new_systemd_task_name('dnsreload'), self.path_reload_dns, self.wg_name, current_pubkey, current_endpoint))
                self.flag_require_systemd_clean = True

            if self.flag_is_route_forward and this_peer_idx == 0:
                self.result_postup.insert(0, 'wg set {} peer {} allowed-ips 0.0.0.0/0'.format(self.wg_name, current_pubkey))

            if current_lookup:
                for ip_cidr in current_allowed:
                    self.result_postup.append('ip rule add from {} lookup {}'.format(ip_cidr, current_lookup))
                    self.result_postdown.append('ip rule del from {} lookup {}'.format(ip_cidr, current_lookup))

    def compile_final(self):
        if self.flag_require_tmpfile_clean:
            self.result_postup.insert(0, 'rm -f /tmp/wg-ops-tmpfile-{}-*'.format(self.wg_name))
            self.result_postup.append('rm -f /tmp/wg-ops-tmpfile-{}-*'.format(self.wg_name))

        if self.flag_require_systemd_clean or self.opt_use_systemd:
            self.result_postup.insert(0, 'systemctl stop wg-ops-task-{}-*'.format(self.wg_name))
            self.result_postdown.insert(0, 'systemctl stop wg-ops-task-{}-*'.format(self.wg_name))

    def get_result(self):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        gen_result_postup = ["PostUp={}".format(line) for line in self.result_postup]
        gen_result_postdown = ["PostDown={}".format(line) for line in self.result_postdown]

        return '''# Generated by wg-ops at {}. DO NOT EDIT.
{}
{}
{}
{}
'''.format(current_time, '\n'.join(self.result_interface), '\n'.join(gen_result_postup), '\n'.join(gen_result_postdown), '\n'.join(self.result_peers))
