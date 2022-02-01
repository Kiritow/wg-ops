import os
import sys
import this
import time
import getopt


path_udp2raw = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'bin/udp2raw_amd64')
path_w2u = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'bin/w2u')
path_gost = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'bin/gost')


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

        # flags
        self.flag_has_setup_tmux = False
        self.flag_is_route_forward = False
        self.flag_is_route_lookup = False

        # vars
        self.wg_name = '%i'
        self.wg_port = 0
        self.wg_mtu = 0
        self.idx_tunnels = {}
        self.lookup_table = ''
    
    def enable_tmux(self):
        if not self.flag_has_setup_tmux:
            self.flag_has_setup_tmux = True
            self.result_postup.append('''PostUp=/usr/bin/tmux new-session -s tunnel-{} -d 'watch -n 1 --color WG_COLOR_MODE=always wg show {}' '''.format(self.wg_name, self.wg_name))
            self.result_postdown.append('PostDown=sleep 1; /usr/bin/tmux kill-session -t tunnel-{}'.format(self.wg_name))

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
            elif line.startswith('#udp2raw-server'):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_passwd = parts[2]

                self.enable_tmux()

                self.result_postup.append('''PostUp=echo -e '-s\\n-l 0.0.0.0:{}\\n-r 127.0.0.1:{}\\n-k {}\\n--raw-mode faketcp\\n--fix-gro\\n-a' > /tmp/temp-udp2raw-{}.conf'''.format(
                    tunnel_port, self.wg_port, tunnel_passwd, tunnel_name
                ))
                self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} --conf-file /tmp/temp-udp2raw-{}.conf'; sleep 2'''.format(
                    self.wg_name, path_udp2raw, tunnel_name
                ))
                self.result_postup.append('''PostUp=rm /tmp/temp-udp2raw-{}.conf'''.format(tunnel_name))
            elif line.startswith('#udp2raw-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_remote = parts[2]
                tunnel_passwd = parts[3]

                self.idx_tunnels[tunnel_name] = tunnel_port
                self.enable_tmux()

                self.result_postup.append('''PostUp=echo -e '-c\\n-l 127.0.0.1:{}\\n-r {}\\n-k {}\\n--raw-mode faketcp\\n--fix-gro\\n-a' > /tmp/temp-udp2raw-{}.conf'''.format(
                    tunnel_port, tunnel_remote, tunnel_passwd, tunnel_name
                ))
                self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -n {}-win -d '{} --conf-file /tmp/temp-udp2raw-{}.conf'; sleep 2'''.format(
                    self.wg_name, tunnel_name, path_udp2raw, tunnel_name
                ))
                self.result_postup.append('''PostUp=rm /tmp/temp-udp2raw-{}.conf'''.format(tunnel_name))
                self.result_postdown.append('''PostDown=/usr/bin/tmux send-keys -t {}-win C-c '''.format(tunnel_name))
            elif line.startswith('#udp2raw-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = int(parts[1])
                tunnel_port = int(parts[2])
                tunnel_remote = parts[3]
                tunnel_passwd = parts[4]

                self.idx_tunnels[tunnel_name] = tunnel_port
                self.enable_tmux()

                self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -f {} -l {} -t {} -s {}' '''.format(
                    self.wg_name, path_w2u, self.wg_port, tunnel_port, tunnel_port + 1, tunnel_mux
                ))
                for mux_idx in range(tunnel_mux):
                    self.result_postup.append('''PostUp=echo -e '-c\\n-l 127.0.0.1:{}\\n-r {}\\n-k {}\\n--raw-mode faketcp\\n--fix-gro\\n-a' > /tmp/temp-udp2raw-{}-{}.conf'''.format(
                        tunnel_port + 1 + mux_idx, tunnel_remote, tunnel_passwd, tunnel_name, mux_idx
                    ))
                    self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -n {}-win-{} -d '{} --conf-file /tmp/temp-udp2raw-{}-{}.conf'; sleep 2'''.format(
                        self.wg_name, tunnel_name, mux_idx, path_udp2raw, tunnel_name, mux_idx
                    ))
                    self.result_postup.append('''PostUp=rm /tmp/temp-udp2raw-{}-{}.conf'''.format(tunnel_name, mux_idx))

                    self.result_postdown.append('''PostDown=/usr/bin/tmux send-keys -t {}-win-{} C-c '''.format(tunnel_name, mux_idx))

            elif line.startswith('#gost-server '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]

                self.enable_tmux()

                self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -L=relay+tls://:{}/127.0.0.1:{}' '''.format(
                    self.wg_name, path_gost, tunnel_port, self.wg_port
                ))
            elif line.startswith('#gost-client '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_port = parts[1]
                tunnel_remote = parts[2]

                self.idx_tunnels[tunnel_name] = tunnel_port
                self.enable_tmux()

                self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -L udp://:{} -F relay+tls://{}' '''.format(
                    self.wg_name, path_gost, tunnel_port, tunnel_remote
                ))
            elif line.startswith('#gost-client-mux '):
                parts = line.split(' ')[1:]
                tunnel_name = parts[0]
                tunnel_mux = int(parts[1])
                tunnel_port = int(parts[2])
                tunnel_remote = parts[3]

                self.idx_tunnels[tunnel_name] = tunnel_port
                self.enable_tmux()

                self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -f {} -l {} -t {} -s {}' '''.format(
                    self.wg_name, path_w2u, self.wg_port, tunnel_port, tunnel_port + 1, tunnel_mux
                ))
                for mux_idx in range(tunnel_mux):
                    self.result_postup.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -L udp://:{} -F relay+tls://{}' '''.format(
                        self.wg_name, path_gost, tunnel_port + 1 + mux_idx, tunnel_remote
                    ))
            else:
                sys.stderr.write('[WARN] comment or unknown hint: {}\n'.format(line))
        
        if not self.wg_mtu:
            sys.stderr.write('[WARN] MTU not detected, using suggested mtu value (1280).\n')
            self.result_interface.append('MTU=1280')

    def compile_peers(self):
        if self.flag_is_route_forward and len(self.input_peer) > 1:
            sys.stderr.write('[WARN] route-forward should used with ONLY one peer.')

        for this_peer_idx, this_peer_lines in enumerate(self.input_peer):
            current_pubkey = ''
            current_allowed = ''
            self.result_peers.append('[Peer]')

            for line in this_peer_lines:
                if line.startswith('PublicKey'):
                    current_pubkey =  line.split('=')[1].strip()
                if line.startswith('AllowedIPs'):
                    current_allowed = line.split('=')[1].strip().split(',') 

                if not line.startswith('#'):
                    self.result_peers.append(line)
                    continue

                if line.startswith('#use-tunnel'):
                    parts = line.split(' ')[1:]
                    tunnel_name = parts[0]

                    tunnel_port = self.idx_tunnels[tunnel_name]
                    self.result_peers.append('Endpoint=127.0.0.1:{}'.format(tunnel_port))
                else:
                    sys.stderr.write('[WARN] comment or unknown hint: {}\n'.format(line))

            if self.flag_is_route_forward and this_peer_idx == 0:
                self.result_postup.insert(0, 'PostUp=wg set {} peer {} allowed-ips 0.0.0.0/0'.format(self.wg_name, current_pubkey))
            
            if self.flag_is_route_lookup:
                for ip_cidr in current_allowed:
                    self.result_postup.append('PostUp=ip rule add from {} lookup {}'.format(ip_cidr, self.lookup_table))
                    self.result_postup.append('PostUp=ip rule del from {} lookup {}'.format(ip_cidr, self.lookup_table))
    
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

    with open(filename, 'r') as f:
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
