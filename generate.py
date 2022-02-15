import os
import sys
import time
import getopt
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


wgop_basepath = os.path.dirname(os.path.realpath(sys.argv[0]))

path_get_gateway = os.path.join(wgop_basepath, 'tools/get-gateway.py')
path_get_ip = os.path.join(wgop_basepath, 'tools/get-ip.py')
path_get_lan_ip = os.path.join(wgop_basepath, 'tools/get-lan-ip.py')
path_bin_dir = os.path.join(wgop_basepath, 'bin')
path_app_dir = os.path.join(wgop_basepath, 'app')


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


def get_rsa_keypair_from_pem(private_pem):
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    public_key = private_key.public_key()
    return private_key, public_key


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
    )))


def rsa_decrypt_base64(private_key, data):
    return private_key.decrypt(base64.b64decode(data), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))


class Parser:
    def __init__(self):
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
        self.flag_allow_modify = False

        # opts
        self.opt_source_path = ''

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
        self.pending_peers = []
        self.pending_accepts = []
        self.tunnel_local_endpoint = {}
        self.tunnel_server_reports = {}
        self.lookup_table = ''
        self.container_expose_port = []
        self.container_bootstrap = []
        self.podman_user = ''

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

    def registry_resolve(self, client_name):
        if not self.registry_domain:
            errprint('[ERROR] Cannot query from registry, domain not specified')
            exit(1)
        if not self.registry_client_name:
            errprint('[ERROR] No registry client name found.')
            exit(1)

        errprint('Resolving client {} from registry ({})...'.format(client_name, self.registry_domain))
        try:
            res = requests.get('{}/query'.format(self.registry_domain), params={
                "name": client_name,
            })

            remote_result = res.json()
            remote_peers = remote_result['peers']
            if self.registry_client_name not in remote_peers:
                errprint('This client ({}) is not accepted by {}'.format(self.registry_client_name, client_name))
                return {}

            remote_config = rsa_decrypt_base64(remote_peers[self.registry_client_name])
            return json.loads(remote_config)
        except Exception:
            errprint(traceback.format_exc())
            errprint('Exception happened during registry client resolve')
            return {}

    def registry_upload(self, content):
        if not self.registry_domain:
            errprint('[ERROR] Cannot query from registry, domain not specified')
            exit(1)
        if not self.registry_client_name:
            errprint('[ERROR] No registry client name found.')
            exit(1)

        errprint('Registering this client ({}) with registry ({})...'.format(self.registry_client_name, self.registry_domain))
        try:
            res = requests.post('{}/register'.format(self.registry_domain), json=content)
            res = res.json()

            errprint('[REGISTRY] {}'.format(res['message']))
            if res['code'] < 0:
                return False
            else:
                return True
        except Exception:
            errprint(traceback.format_exc())
            errprint('Exception happened during registry register')
            return False

    def registry_ensure(self):
        private_pem, public_pem = get_pem_from_rsa_keypair(None, self.local_public_key)
        can_ensure = self.registry_upload({
            "name": self.registry_client_name,
            "pubkey": public_pem,
            "wgkey": self.wg_pubkey,
            "peers": {},
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

    def add_muxer(self, listen_port, forward_start, forward_size):
        self.container_bootstrap.append({
            "type": "mux",
            "listen": int(listen_port),
            "forward": int(forward_start),
            "size": int(forward_size),
        })

    def add_gost_server(self, tunnel_name, listen_port):
        self.container_bootstrap.append({
            "type": "gost-server",
            "listen": int(listen_port),
        })
        self.tunnel_server_reports[tunnel_name] = {
            "type": "gost",
            "listen": int(listen_port),
        }

    def add_gost_client_with(self, remote_config):
        self.local_autogen_nextport += 1
        tunnel_name = "gen{}{}".format(self.wg_hash[:8], self.local_autogen_nextport)
        self.add_gost_client(tunnel_name, self.local_autogen_nextport, "{}:{}".format(remote_config['ip'], remote_config['listen']))

    def add_gost_client_mux(self, tunnel_name, mux_size, listen_port, tunnel_remote):
        if self.podman_user:
            self.add_expose(listen_port)
            self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        else:
            self.tunnel_local_endpoint[tunnel_name] = "gateway:{}".format(listen_port)
        self.add_muxer(listen_port, listen_port+1, mux_size)
        for mux_idx in range(mux_size):
            self._do_add_gost_client(listen_port + 1 + mux_idx, tunnel_remote)

    def add_gost_client(self, tunnel_name, listen_port, tunnel_remote):
        if self.podman_user:
            self.add_expose(listen_port)
            self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        else:
            self.tunnel_local_endpoint[tunnel_name] = "gateway:{}".format(listen_port)
        self._do_add_gost_client(listen_port, tunnel_remote)

    def _do_add_gost_client(self, listen_port, tunnel_remote):
        self.container_bootstrap.append({
            "type": "gost-client",
            "listen": int(listen_port),
            "remote": tunnel_remote,
        })

    def add_udp2raw_server(self, tunnel_name, listen_port, tunnel_password):
        conf_uuid = str(uuid.uuid4())

        self.container_bootstrap.append({
            "type": "udp2raw-server",
            "listen": int(listen_port),
            "password": tunnel_password,
            "id": conf_uuid,
        })
        self.tunnel_server_reports[tunnel_name] = {
            "type": "udp2raw",
            "listen": int(listen_port),
            "password": tunnel_password,
        }

        ipt_filename_inside = "/root/conf/{}-ipt.conf".format(conf_uuid)

        self.result_container_postbootstrap.append('PostUp=IPT_COMMANDS=$({}); echo $IPT_COMMANDS; $IPT_COMMANDS'.format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))
        self.result_postdown.append("PostDown=IPT_COMMANDS=$({}); IPT_COMMANDS=$(echo $IPT_COMMANDS | sed -e 's/-I /-D /g'); echo $IPT_COMMANDS; $IPT_COMMANDS".format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))

    def add_udp2raw_client_with(self, remote_config):
        self.local_autogen_nextport += 1
        tunnel_name = "gen{}{}".format(self.wg_hash[:8], self.local_autogen_nextport)
        self.add_udp2raw_client(tunnel_name, self.local_autogen_nextport, remote_config["password"], "{}:{}".format(remote_config['ip'], remote_config['listen']))

    def add_udp2raw_client_mux(self, tunnel_name, mux_size, listen_port, tunnel_password, remote_addr):
        self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        self.flag_container_must_host = True
        self.add_muxer(listen_port, listen_port+1, mux_size)
        for mux_idx in range(mux_size):
            self._do_add_udp2raw_client(listen_port + 1 + mux_idx, tunnel_password, remote_addr)

    def add_udp2raw_client(self, tunnel_name, listen_port, tunnel_password, remote_addr):
        self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        self.flag_container_must_host = True
        self._do_add_udp2raw_client(listen_port, tunnel_password, remote_addr)

    def _do_add_udp2raw_client(self, listen_port, tunnel_password, remote_addr):
        conf_uuid = str(uuid.uuid4())

        self.container_bootstrap.append({
            "type": "udp2raw-client",
            "listen": int(listen_port),
            "password": tunnel_password,
            "remote": remote_addr,
            "id": conf_uuid,
        })

        ipt_filename_inside = "/root/conf/{}-ipt.conf".format(conf_uuid)

        self.result_container_postbootstrap.append('PostUp=IPT_COMMANDS=$({}); echo $IPT_COMMANDS; $IPT_COMMANDS'.format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))
        self.result_postdown.append("PostDown=IPT_COMMANDS=$({}); IPT_COMMANDS=$(echo $IPT_COMMANDS | sed -e 's/-I /-D /g'); echo $IPT_COMMANDS; $IPT_COMMANDS".format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))

    def add_trojan_server(self, tunnel_name, listen_port, tunnel_password, ssl_cert_path, ssl_key_path):
        cert_uuid = str(uuid.uuid4())
        cert_filepath = "/root/ssl/{}.cert".format(cert_uuid)
        key_filepath = "/root/ssl/{}.key".format(cert_uuid)

        self.result_container_prebootstrap.append('PostUp={}'.format(
            self.get_podman_cmd_with('podman cp {} {}:{}'.format(ssl_cert_path, self.get_container_name(), cert_filepath))
        ))
        self.result_container_prebootstrap.append('PostUp={}'.format(
            self.get_podman_cmd_with('podman cp {} {}:{}'.format(ssl_key_path, self.get_container_name(), key_filepath))
        ))

        self.container_bootstrap.append({
            "type": "trojan-server",
            "listen": int(listen_port),
            "password": tunnel_password,
            "cert": cert_uuid,
        })
        self.tunnel_server_reports[tunnel_name] = {
            "type": "trojan",
            "listen": int(listen_port),
            "password": tunnel_password,
            "target": int(self.wg_port),
            "sni": get_subject_name_from_cert(ssl_cert_path),
        }

    def add_trojan_client_with(self, remote_config):
        self.local_autogen_nextport += 1
        tunnel_name = "gen{}{}".format(self.wg_hash[:8], self.local_autogen_nextport)
        self.add_trojan_client(tunnel_name, self.local_autogen_nextport, remote_config["password"],
            "{}:{}".format(remote_config["ip"], remote_config["listen"]), remote_config["target"], ssl_sni=remote_config["sni"])

    def add_trojan_client_mux(self, tunnel_name, mux_size, listen_port, tunnel_password, remote_addr, target_port, ssl_sni=None):
        if self.podman_user:
            self.add_expose(listen_port)
            self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        else:
            self.tunnel_local_endpoint[tunnel_name] = "gateway:{}".format(listen_port)
        self.add_muxer(listen_port, listen_port+1, mux_size)
        for mux_idx in range(mux_size):
            self._do_add_trojan_client(listen_port + 1 + mux_idx, tunnel_password, remote_addr, target_port, ssl_sni)

    def add_trojan_client(self, tunnel_name, listen_port, tunnel_password, remote_addr, target_port, ssl_sni=None):
        if self.podman_user:
            self.add_expose(listen_port)
            self.tunnel_local_endpoint[tunnel_name] = "127.0.0.1:{}".format(listen_port)
        else:
            self.tunnel_local_endpoint[tunnel_name] = "gateway:{}".format(listen_port)
        self._do_add_trojan_client(listen_port, tunnel_password, remote_addr, target_port, ssl_sni)

    def _do_add_trojan_client(self, listen_port, tunnel_password, remote_addr, target_port, ssl_sni):
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

                self.local_private_key, self.local_public_key = get_rsa_keypair_from_pem(private_pem)
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

        filted_input_interface = []
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

                self.pending_accepts.append({
                    "tunnel": tunnel_name,
                    "client": client_name,
                    "ip": client_ip,
                    "allowed": client_allowed,
                })
                self.flag_require_registry = True
            else:
                filted_input_interface.append(line)

        # registry init
        if self.flag_require_registry:
            if not self.local_private_key:
                errprint('registry required but no existing private key found, generating new...')

                self.local_private_key, self.local_public_key = generate_rsa_keypair()
                private_pem, public_pem = get_pem_from_rsa_keypair(self.local_private_key, self.local_public_key)

                if self.flag_allow_modify:
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
                errprint('Resolving connect-to {}...'.format(peer_client_name))
                peer_config = self.registry_resolve(peer_client_name)
                {
                    "udp2raw": self.add_udp2raw_client_with,
                    "gost": self.add_gost_client_with,
                    "trojan": self.add_trojan_client_with,
                }.get(peer_config["type"], lambda x: x)(peer_config)

        # compile interface
        for line in filted_input_interface:
            if not line.startswith('#'):
                self.result_interface.append(line)
                continue

            elif line.startswith('#enable-bbr'):
                self.result_postup.append('PostUp=sysctl net.core.default_qdisc=fq\nPostUp=sysctl net.ipv4.tcp_congestion_control=bbr')
            elif line.startswith('#enable-forward'):
                self.result_postup.append('PostUp=sysctl net.ipv4.ip_forward=1')
            elif line.startswith('#iptables-forward'):
                self.result_postup.append('PostUp=iptables -A FORWARD -i {} -j ACCEPT'.format(self.wg_name))
                self.result_postdown.append('PostDown=iptables -D FORWARD -i {} -j ACCEPT'.format(self.wg_name))
            elif line.startswith('#route-to'):
                self.flag_is_route_forward = True

                parts = line.split(' ')[1:]
                table_name = parts[0]

                self.result_postup.append('PostUp=ip route add 0.0.0.0/0 dev {} table {}'.format(self.wg_name, table_name))
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

                self.podman_user = user_name
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

        if not self.wg_mtu:
            errprint('[WARN] MTU not detected, using suggested mtu value (1280).')
            self.result_interface.append('MTU=1280')

        if self.container_bootstrap:
            config_str = json.dumps(self.container_bootstrap, ensure_ascii=False)
            config_gen = base64.b64encode(config_str.encode()).decode()

            config_parts = []
            while len(config_gen) > 1024:
                config_parts.append(config_gen[:1024])
                config_gen = config_gen[1024:]
            config_parts.append(config_gen)

            tmp_base64_filepath = "/tmp/wg-op-container-bootstrap-{}.data".format(self.wg_name)
            tmp_filepath = "/tmp/wg-op-container-bootstrap-{}.json".format(self.wg_name)

            self.result_postup.append('PostUp=rm -f {}'.format(tmp_base64_filepath))
            for this_config_line in config_parts:
                self.result_postup.append('PostUp=echo {} >> {}'.format(this_config_line, tmp_base64_filepath))
            self.result_postup.append('PostUp=base64 -d {} > {}'.format(tmp_base64_filepath, tmp_filepath))
            self.result_postup.append('PostUp=rm {}'.format(tmp_base64_filepath))

            self.result_container_prebootstrap.append('PostUp={}'.format(
                self.get_podman_cmd_with('podman cp {} {}:/root/conf/bootstrap.json'.format(tmp_filepath, self.get_container_name()))
            ))
            self.result_container_prebootstrap.append('PostUp=rm {}'.format(tmp_filepath))

        if self.result_container_prebootstrap or self.result_container_postbootstrap:
            if not self.flag_container_must_host:
                self.result_postup.append('PostUp={}'.format(
                    self.get_podman_cmd_with('podman network create {}'.format(self.get_container_network_name()))
                ))

            if not self.flag_container_must_host and self.container_expose_port:
                cmd_ports = ["-p {}:{}/{}".format(this_port['port'], this_port['port'], this_port['mode']) for this_port in self.container_expose_port]
                cmd_ports = ' '.join(cmd_ports)
            else:
                cmd_ports = ''

            self.result_postup.append('PostUp={}'.format(
                self.get_podman_cmd_with('podman run --rm --cap-add NET_RAW -v {}:/root/bin -v {}:/root/app {} --name {} --network {} -d wg-ops-runenv'.format(
                    path_bin_dir, path_app_dir, cmd_ports, self.get_container_name(), self.get_container_network_name()))
            ))
            self.result_postup.append('PostUp={}'.format(
                self.get_podman_cmd_with('podman exec {} mkdir -p /root/ssl /root/runner /root/conf'.format(
                    self.get_container_name()))
            ))
            self.result_postdown.append('PostDown={}'.format(
                self.get_podman_cmd_with('podman stop {}'.format(self.get_container_name()))
            ))

            if not self.flag_container_must_host:
                self.result_postdown.append('PostDown={}'.format(
                    self.get_podman_cmd_with('podman network rm {}'.format(self.get_container_network_name()))
                ))

            self.result_postup.extend(self.result_container_prebootstrap)

            if self.flag_container_must_host:
                self.result_postup.append('PostUp={}'.format(
                    self.get_podman_cmd_with('podman exec -t -e GATEWAY_IP=127.0.0.1 -e WG_PORT={} {} /usr/bin/python3 /root/app/bootstrap.py'.format(
                        self.wg_port, self.get_container_name()))
                ))
            elif self.podman_user:
                self.result_postup.append('PostUp={}'.format(
                    self.get_podman_cmd_with('CT_GATEWAY=$(/usr/bin/python3 {}); podman exec -t -e GATEWAY_IP=$CT_GATEWAY -e WG_PORT={} {} /usr/bin/python3 /root/app/bootstrap.py'.format(
                        path_get_lan_ip, self.wg_port, self.get_container_name()))
                ))
            else:
                self.result_postup.append('PostUp={}'.format(
                    self.get_podman_cmd_with('CT_GATEWAY=$(/usr/bin/python3 {} {}); podman exec -t -e GATEWAY_IP=$CT_GATEWAY -e WG_PORT={} {} /usr/bin/python3 /root/app/bootstrap.py'.format(
                        path_get_gateway, self.get_container_network_name(), self.wg_port, self.get_container_name()))
                ))

            self.result_postup.extend(self.result_container_postbootstrap)

    def compile_peers(self):
        if self.flag_is_route_forward and len(self.input_peer) > 1:
            errprint('[WARN] route-forward should used with ONLY one peer.')

        for this_peer_idx, this_peer_lines in enumerate(self.input_peer):
            current_pubkey = ''
            current_allowed = ''
            if self.flag_is_route_lookup:
                current_lookup = self.lookup_table
            else:
                current_lookup = ''

            # pre-scan
            for line in this_peer_lines:
                if line.startswith('PublicKey'):
                    current_pubkey =  '='.join(line.split('=')[1:])
                if line.startswith('AllowedIPs'):
                    current_allowed = line.split('=')[1].strip().split(',') 

            self.result_peers.append('[Peer]')

            for line in this_peer_lines:
                if not line.startswith('#'):
                    self.result_peers.append(line)
                    continue

                if line.startswith('#use-tunnel'):
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
                                self.result_postup.append("PostUp=wg set {} peer {} endpoint 127.0.0.1:{}".format(
                                    self.wg_name, current_pubkey, addr_port))
                            else:
                                self.result_postup.append("PostUp=CT_IP=$({}); wg set {} peer {} endpoint $CT_IP:{}".format(
                                    self.get_podman_cmd_with('/usr/bin/python3 {} {} {}'.format(path_get_ip, self.get_container_network_name(), self.get_container_name())),
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
                else:
                    errprint('[WARN] comment or unknown hint: {}'.format(line))

            if self.flag_is_route_forward and this_peer_idx == 0:
                self.result_postup.insert(0, 'PostUp=wg set {} peer {} allowed-ips 0.0.0.0/0'.format(self.wg_name, current_pubkey))

            if current_lookup:
                for ip_cidr in current_allowed:
                    self.result_postup.append('PostUp=ip rule add from {} lookup {}'.format(ip_cidr, current_lookup))
                    self.result_postdown.append('PostDown=ip rule del from {} lookup {}'.format(ip_cidr, current_lookup))
    
    def get_result(self):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        return '''# Generated by wg-ops at {}. DO NOT EDIT.
{}
{}
{}
{}
'''.format(current_time, '\n'.join(self.result_interface), '\n'.join(self.result_postup), '\n'.join(self.result_postdown), '\n'.join(self.result_peers))


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], 'hiko:')
    opts = {p[0]: p[1] for p in opts}

    if '-h' in opts:
        print('''wg-ops: WireGuard configuration extended generator
OPTIONS
    -h Display this help and quit.
    -k Output generated config to standard output
    -o <filename> Output generated config to file. Default is {source_filename}.gen
HELP
    For latest help please view https://github.com/Kiritow/wg-ops
''')
        exit(0)

    filepath = args[0]
    filename = os.path.basename(filepath)

    with open(filepath, 'r') as f:
        content = f.read()

    parser = Parser()
    if '-i' in opts:
        parser.flag_allow_modify = True
        parser.opt_source_path = filepath

    parser.parse(content)
    parser.compile_interface()
    parser.compile_peers()

    if '-k' in opts or ('-o' in opts and opts['-o'] == '-'):
        print(parser.get_result())
    elif '-o' in opts:
        errprint('Saving to {}...'.format(opts['-o']))
        with open(opts['-o'], 'w') as f:
            f.write(parser.get_result())
    else:
        errprint('Saving to {}.gen...'.format(filename))
        with open('{}.gen'.format(filename), 'w') as f:
            f.write(parser.get_result())
