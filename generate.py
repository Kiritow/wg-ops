import os
import sys
import time

filepath = sys.argv[1]

path_udp2raw = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'bin/udp2raw_amd64')
path_w2u = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'bin/w2u')
path_gost = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'bin/gost')

filename = os.path.basename(filepath)
wg_name = filename.split('.')[0]

with open(filename, 'r') as f:
    content = f.read().split('\n')

gen_ctx = {
    'tunnels': {},
    'post_down': [],
}

results = []


def add_tmux_session_once():
    if 'has_setup_tmux' not in gen_ctx:
        gen_ctx['has_setup_tmux'] = True
        results.append('''PostUp=/usr/bin/tmux new-session -s tunnel-{} -d 'watch -n 1 --color WG_COLOR_MODE=always wg show {}' '''.format(wg_name, wg_name))

for line in content:
    if line.startswith('ListenPort'):
        gen_ctx['wg_port'] = int(line.split('=')[1])
    if line.startswith('[Peer]'):
        if 'peer_started' not in gen_ctx:
            gen_ctx['peer_started'] = True
            if gen_ctx['post_down']:
                results.extend(gen_ctx['post_down'])

            if 'has_setup_tmux' in gen_ctx:
                results.append('PostDown=sleep 1; /usr/bin/tmux kill-session -t tunnel-{}'.format(wg_name))

    if not line.startswith('#'):
        results.append(line)
        continue
    
    if line.startswith('#enable-bbr'):
        results.append('PostUp=sysctl net.core.default_qdisc=fq\nPostUp=sysctl net.ipv4.tcp_congestion_control=bbr')
    elif line.startswith('#enable-forward'):
        results.append('PostUp=sysctl net.ipv4.ip_forward=1')
    elif line.startswith('#iptables-forward'):
        results.append('PostUp=iptables -A FORWARD -i {} -j ACCEPT'.format(wg_name))
        gen_ctx['post_down'].append('PostDown=iptables -D FORWARD -i {} -j ACCEPT'.format(wg_name))
    elif line.startswith('#udp2raw-server'):
        parts = line.split(' ')[1:]
        tunnel_name = parts[0]
        tunnel_port = parts[1]
        tunnel_passwd = parts[2]

        add_tmux_session_once()

        results.append('''PostUp=/usr/bin/echo -e '-s\\n-l 0.0.0.0:{}\\n-r 127.0.0.1:{}\\n-k {}\\n--raw-mode faketcp\\n--fix-gro\\n-a' > /tmp/temp-udp2raw-{}.conf'''.format(
            tunnel_port, gen_ctx['wg_port'], tunnel_passwd, tunnel_name
        ))
        results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} --conf-file /tmp/temp-udp2raw-{}.conf'; sleep 2'''.format(
            wg_name, path_udp2raw, tunnel_name
        ))
        results.append('''PostUp=/usr/bin/rm /tmp/temp-udp2raw-{}.conf'''.format(tunnel_name))
    elif line.startswith('#udp2raw-client '):
        parts = line.split(' ')[1:]
        tunnel_name = parts[0]
        tunnel_port = parts[1]
        tunnel_remote = parts[2]
        tunnel_passwd = parts[3]

        gen_ctx['tunnels'][tunnel_name] = tunnel_port
        add_tmux_session_once()

        results.append('''PostUp=/usr/bin/echo -e '-c\\n-l 127.0.0.1:{}\\n-r {}\\n-k {}\\n--raw-mode faketcp\\n--fix-gro\\n-a' > /tmp/temp-udp2raw-{}.conf'''.format(
            tunnel_port, tunnel_remote, tunnel_passwd, tunnel_name
        ))
        results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -n {}-win -d '{} --conf-file /tmp/temp-udp2raw-{}.conf'; sleep 2'''.format(
            wg_name, tunnel_name, path_udp2raw, tunnel_name
        ))
        results.append('''PostUp=/usr/bin/rm /tmp/temp-udp2raw-{}.conf'''.format(tunnel_name))

        gen_ctx['post_down'].append('''PostDown=/usr/bin/tmux send-keys -t {}-win C-c '''.format(tunnel_name))
    elif line.startswith('#udp2raw-client-mux '):
        parts = line.split(' ')[1:]
        tunnel_name = parts[0]
        tunnel_mux = int(parts[1])
        tunnel_port = int(parts[2])
        tunnel_remote = parts[3]
        tunnel_passwd = parts[4]

        gen_ctx['tunnels'][tunnel_name] = tunnel_port
        add_tmux_session_once()

        results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -f {} -l {} -t {} -s {}' '''.format(
            wg_name, path_w2u, gen_ctx['wg_port'], tunnel_port, tunnel_port + 1, tunnel_mux
        ))
        for mux_idx in range(tunnel_mux):
            results.append('''PostUp=/usr/bin/echo -e '-c\\n-l 127.0.0.1:{}\\n-r {}\\n-k {}\\n--raw-mode faketcp\\n--fix-gro\\n-a' > /tmp/temp-udp2raw-{}-{}.conf'''.format(
                tunnel_port + 1 + mux_idx, tunnel_remote, tunnel_passwd, tunnel_name, mux_idx
            ))
            results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -n {}-win-{} -d '{} --conf-file /tmp/temp-udp2raw-{}-{}.conf'; sleep 2'''.format(
                wg_name, tunnel_name, mux_idx, path_udp2raw, tunnel_name, mux_idx
            ))
            results.append('''PostUp=/usr/bin/rm /tmp/temp-udp2raw-{}-{}.conf'''.format(tunnel_name, mux_idx))

            gen_ctx['post_down'].append('''PostDown=/usr/bin/tmux send-keys -t {}-win-{} C-c '''.format(tunnel_name, mux_idx))

    elif line.startswith('#gost-server '):
        parts = line.split(' ')[1:]
        tunnel_name = parts[0]
        tunnel_port = parts[1]

        add_tmux_session_once()

        results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -L=relay+tls://:{}/127.0.0.1:{}' '''.format(
            wg_name, path_gost, tunnel_port, gen_ctx['wg_port']
        ))
    elif line.startswith('#gost-client '):
        parts = line.split(' ')[1:]
        tunnel_name = parts[0]
        tunnel_port = parts[1]
        tunnel_remote = parts[2]

        gen_ctx['tunnels'][tunnel_name] = tunnel_port
        add_tmux_session_once()

        results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -L udp://:{} -F relay+tls://{}' '''.format(
            wg_name, path_gost, tunnel_port, tunnel_remote
        ))
    elif line.startswith('#gost-client-mux '):
        parts = line.split(' ')[1:]
        tunnel_name = parts[0]
        tunnel_mux = int(parts[1])
        tunnel_port = int(parts[2])
        tunnel_remote = parts[3]

        gen_ctx['tunnels'][tunnel_name] = tunnel_port
        add_tmux_session_once()

        results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -f {} -l {} -t {} -s {}' '''.format(
            wg_name, path_w2u, gen_ctx['wg_port'], tunnel_port, tunnel_port + 1, tunnel_mux
        ))
        for mux_idx in range(tunnel_mux):
            results.append('''PostUp=/usr/bin/tmux new-window -t tunnel-{} -d '{} -L udp://:{} -F relay+tls://{}' '''.format(
                wg_name, path_gost, tunnel_port + 1 + mux_idx, tunnel_remote
            ))
    elif line.startswith('#use-tunnel'):
        parts = line.split(' ')[1:]
        tunnel_name = parts[0]

        tunnel_port = gen_ctx['tunnels'][tunnel_name]
        results.append('Endpoint=127.0.0.1:{}'.format(tunnel_port))
    elif line.startswith('#route'):
        parts = line.split(' ')[1:]
        route_target = parts[0]

        if 'disable_table' not in gen_ctx:
            gen_ctx['disable_table'] = True
            results.insert(1, 'Table=off')
        
        # find last post-up
        prev_postup = False
        last_postup_idx = 0
        for i in range(len(results)):
            if results[i].startswith('PostUp='):
                prev_postup = True
                continue
            if prev_postup:
                last_postup_idx = i
                break
        if not last_postup_idx:
            results.append('PostUp=ip -4 route add {} dev wg0'.format(route_target))
        else:
            results.insert(last_postup_idx, 'PostUp=ip -4 route add {} dev wg0'.format(route_target))
    else:
        print('[WARN] comment or unknown hint: {}'.format(line))


with open('{}.gen'.format(filename), 'w') as f:
    f.write('# Generated by wg-ops at {}. DO NOT EDIT\n'.format(time.strftime("%Y-%m-%d %H:%M:%S")))
    f.write('\n'.join(results))
