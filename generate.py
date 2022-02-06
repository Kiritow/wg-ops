import os
import sys
import time
import getopt
import uuid
import json
import base64


wgop_basepath = os.path.dirname(os.path.realpath(sys.argv[0]))

path_get_gateway = os.path.join(wgop_basepath, 'tools/get-gateway.py')
path_get_ip = os.path.join(wgop_basepath, 'tools/get-ip.py')
path_get_lan_ip = os.path.join(wgop_basepath, 'tools/get-lan-ip.py')
path_bin_dir = os.path.join(wgop_basepath, 'bin')
path_app_dir = os.path.join(wgop_basepath, 'app')


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

        # vars
        self.wg_name = '%i'
        self.wg_port = 0
        self.wg_mtu = 0
        self.idx_tunnels = {}
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

    def add_expose(self, expose_port, mode='udp'):
        self.container_expose_port.append({
            "port": expose_port,
            "mode": mode,
        })

    def add_muxer(self, listen_port, forward_start, forward_size):
        self.container_bootstrap.append({
            "type": "mux",
            "listen": listen_port,
            "forward": forward_start,
            "size": forward_size,
        })

    def add_gost_server(self, listen_port):
        self.container_bootstrap.append({
            "type": "gost-server",
            "listen": listen_port,
        })

    def add_gost_client(self, listen_port, tunnel_remote):
        self.container_bootstrap.append({
            "type": "gost-client",
            "listen": listen_port,
            "remote": tunnel_remote,
        })

    def add_udp2raw_server(self, listen_port, tunnel_password):
        conf_uuid = str(uuid.uuid4())

        self.container_bootstrap.append({
            "type": "udp2raw-server",
            "listen": listen_port,
            "password": tunnel_password,
            "id": conf_uuid,
        })

        ipt_filename_inside = "/root/conf/{}-ipt.conf".format(conf_uuid)

        self.result_container_postbootstrap.append('PostUp=IPT_COMMANDS=$({}); echo $IPT_COMMANDS; $IPT_COMMANDS'.format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))
        self.result_postdown.append("PostDown=IPT_COMMANDS=$({}); IPT_COMMANDS=$(echo $IPT_COMMANDS | sed -e 's/-I /-D /g'); echo $IPT_COMMANDS; $IPT_COMMANDS".format(
            self.get_podman_cmd_with("podman exec {} /root/bin/udp2raw_amd64 --conf-file {} | grep ^iptables".format(self.get_container_name(), ipt_filename_inside))
        ))
    
    def add_udp2raw_client(self, listen_port, tunnel_password, remote_addr):
        conf_uuid = str(uuid.uuid4())

        self.container_bootstrap.append({
            "type": "udp2raw-client",
            "listen": listen_port,
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

    def add_trojan_server(self, listen_port, tunnel_password, ssl_cert_path, ssl_key_path):
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
            "listen": listen_port,
            "password": tunnel_password,
            "cert": cert_uuid,
        })

    def add_trojan_client(self, listen_port, tunnel_password, remote_addr, target_port, ssl_sni=None):
        self.container_bootstrap.append({
            "type": "trojan-client",
            "listen": listen_port,
            "password": tunnel_password,
            "remote": remote_addr,
            "target": target_port,
            "sni": ssl_sni,
        })

    def parse(self, content):
        # parse input
        input_mode = ''
        current_peer = []
        for line in content:
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
                sys.stderr.write('[WARN] Incorrect mode detected with line: {}\n'.format(line))

        if current_peer:
            self.input_peer.append(current_peer)
    
    def compile_interface(self):
        self.result_interface.append('[Interface]')

        # compile interface
        for line in self.input_interface:
            if line.startswith('ListenPort'):
                self.wg_port = int(line.split('=')[1])
            if line.startswith('MTU'):
                self.wg_mtu = int(line.split('=')[1])

            if not line.startswith('#'):
                self.result_interface.append(line)
                continue

            if line.startswith('#enable-bbr'):
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
                sys.stderr.write('[WARN] Please ensure custom route table {} exists.\n'.format(table_name))
            elif line.startswith('#route-from'):
                self.flag_is_route_lookup = True

                parts = line.split(' ')[1:]
                table_name = parts[0]

                self.lookup_table = table_name
                sys.stderr.write('[WARN] Please ensure custom route table {} exists.\n'.format(table_name))
            elif line.startswith('#podman-user'):
                parts = line.split(' ')[1:]
                user_name = parts[0]

                self.podman_user = user_name
            elif line.startswith('#udp2raw-server'):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_passwd = parts[2]

                if self.podman_user:
                    sys.stderr.write('[Error] udp2raw tunnel need root as podman user, got {}\n'.format(self.podman_user))
                    exit(1)

                self.add_udp2raw_server(tunnel_port, tunnel_passwd)
                self.flag_container_must_host = True
            elif line.startswith('#udp2raw-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_remote = parts[2]
                tunnel_passwd = parts[3]

                if self.podman_user:
                    sys.stderr.write('[Error] udp2raw tunnel need root as podman user, got {}\n'.format(self.podman_user))
                    exit(1)

                self.idx_tunnels[tunnel_name] = "127.0.0.1:{}".format(tunnel_port)
                self.add_udp2raw_client(tunnel_port, tunnel_passwd, tunnel_remote)
                self.flag_container_must_host = True
            elif line.startswith('#udp2raw-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = int(parts[1])
                tunnel_port = int(parts[2])
                tunnel_remote = parts[3]
                tunnel_passwd = parts[4]

                if self.podman_user:
                    sys.stderr.write('[Error] udp2raw tunnel need root as podman user, got {}\n'.format(self.podman_user))
                    exit(1)

                self.idx_tunnels[tunnel_name] = "127.0.0.1:{}".format(tunnel_port)
                self.flag_container_must_host = True
                self.add_muxer(tunnel_port, tunnel_port+1, tunnel_mux)
                for mux_idx in range(tunnel_mux):
                    self.add_udp2raw_client(tunnel_port + 1 + mux_idx, tunnel_passwd, tunnel_remote)
            elif line.startswith('#gost-server '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]

                self.add_gost_server(tunnel_port)
                self.add_expose(tunnel_port)
            elif line.startswith('#gost-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_remote = parts[2]

                self.idx_tunnels[tunnel_name] = "gateway:{}".format(tunnel_port)
                self.add_gost_client(tunnel_port, tunnel_remote)

                if self.podman_user:
                    self.add_expose(tunnel_port)
                    self.idx_tunnels[tunnel_name] = "127.0.0.1:{}".format(tunnel_port)
            elif line.startswith('#gost-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = int(parts[1])
                tunnel_port = int(parts[2])
                tunnel_remote = parts[3]

                self.idx_tunnels[tunnel_name] = "gateway:{}".format(tunnel_port)
                self.add_muxer(tunnel_port, tunnel_port+1, tunnel_mux)
                for mux_idx in range(tunnel_mux):
                    self.add_gost_client(tunnel_port + 1 + mux_idx, tunnel_remote)
                
                if self.podman_user:
                    self.add_expose(tunnel_port)
                    self.idx_tunnels[tunnel_name] = "127.0.0.1:{}".format(tunnel_port)
            elif line.startswith('#trojan-server'):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_passwd = parts[2]
                tunnel_cert = parts[3]
                tunnel_key = parts[4]

                self.add_trojan_server(tunnel_port, tunnel_passwd, tunnel_cert, tunnel_key)
                self.add_expose(tunnel_port, mode='tcp')
            elif line.startswith('#trojan-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_passwd = parts[2]
                tunnel_remote = parts[3]
                tunnel_target = parts[4]

                self.idx_tunnels[tunnel_name] = "gateway:{}".format(tunnel_port)
                self.add_trojan_client(tunnel_port, tunnel_passwd, tunnel_remote, tunnel_target)

                if self.podman_user:
                    self.add_expose(tunnel_port)
                    self.idx_tunnels[tunnel_name] = "127.0.0.1:{}".format(tunnel_port)
            elif line.startswith('#trojan-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = parts[1]
                tunnel_port = parts[2]
                tunnel_passwd = parts[3]
                tunnel_remote = parts[4]
                tunnel_target = parts[5]

                self.idx_tunnels[tunnel_name] = "gateway:{}".format(tunnel_port)
                self.add_muxer(tunnel_port, tunnel_port+1, tunnel_mux)
                for mux_idx in range(tunnel_mux):
                    self.add_trojan_client(tunnel_port + 1 + mux_idx, tunnel_passwd, tunnel_remote, tunnel_target)
                
                if self.podman_user:
                    self.add_expose(tunnel_port)
                    self.idx_tunnels[tunnel_name] = "127.0.0.1:{}".format(tunnel_port)
            else:
                sys.stderr.write('[WARN] comment or unknown hint: {}\n'.format(line))

        if not self.wg_mtu:
            sys.stderr.write('[WARN] MTU not detected, using suggested mtu value (1280).\n')
            self.result_interface.append('MTU=1280')
        
        if self.container_bootstrap:
            config_str = json.dumps(self.container_bootstrap)
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
            sys.stderr.write('[WARN] route-forward should used with ONLY one peer.')

        for this_peer_idx, this_peer_lines in enumerate(self.input_peer):
            current_pubkey = ''
            current_allowed = ''
            if self.flag_is_route_lookup:
                current_lookup = self.lookup_table
            else:
                current_lookup = ''

            self.result_peers.append('[Peer]')

            for line in this_peer_lines:
                if line.startswith('PublicKey'):
                    current_pubkey =  '='.join(line.split('=')[1:])
                if line.startswith('AllowedIPs'):
                    current_allowed = line.split('=')[1].strip().split(',') 

                if not line.startswith('#'):
                    self.result_peers.append(line)
                    continue

                if line.startswith('#use-tunnel'):
                    parts = line.split(' ')[1:]
                    tunnel_name = parts[0]

                    tunnel_addr = self.idx_tunnels[tunnel_name]
                    if ":" in tunnel_addr:
                        addr_parts = tunnel_addr.split(':')
                        addr_host = addr_parts[0]
                        addr_port = addr_parts[1]

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
                        sys.stderr.write('[WARN] Please ensure custom route table {} exists.\n'.format(table_name))
                else:
                    sys.stderr.write('[WARN] comment or unknown hint: {}\n'.format(line))

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
    opts, args = getopt.getopt(sys.argv[1:], 'hko:')
    opts = {p[0]: p[1] for p in opts}

    if '-h' in opts:
        print('''wg-ops: WireGuard configuration extended generator
OPTIONS
    -h Display this help and quit.
    -k Output generated config to standard output
    -o <filename> Output generated config to file. Default is {source_filename}.gen
TAGS
    #enable-bbr
    #enable-forward
    #iptables-forward
    #route-to table
    #route-from table
    #udp2raw-server name port password
    #udp2raw-client name port remote password
    #udp2raw-client-mux name mux port remote password
    #gost-server name port
    #gost-client name port remote
    #gost-client-mux name mux port remote
    #use-tunnel name
''')
        exit(0)

    filepath = args[0]
    filename = os.path.basename(filepath)

    with open(filepath, 'r') as f:
        content = f.read().split('\n')

    parser = Parser()
    parser.parse(content)
    parser.compile_interface()
    parser.compile_peers()

    if '-k' in opts or ('-o' in opts and opts['-o'] == '-'):
        print(parser.get_result())
    elif '-o' in opts:
        sys.stderr.write('Saving to {}...\n'.format(opts['-o']))
        with open(opts['-o'], 'w') as f:
            f.write(parser.get_result())
    else:
        sys.stderr.write('Saving to {}.gen...\n'.format(filename))
        with open('{}.gen'.format(filename), 'w') as f:
            f.write(parser.get_result())
