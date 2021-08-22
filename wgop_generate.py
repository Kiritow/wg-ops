# -*- coding: utf-8 -*-
import os
import uuid
from wgop_common import load_config, SimpleLogger


logger = SimpleLogger()


def write_tunnel_config(mode, listen_addr, remote_addr, password):
    filename = "{}.conf".format(uuid.uuid4())
    with open("local/tunnel/{}".format(filename), "w", encoding='utf-8') as f:
        f.write('''
-{}
-l {}
-r {}
-k {}
--raw-mode faketcp
--fix-gro
-a
'''.format(mode, listen_addr, remote_addr, password))
    return filename


tmux_path = os.getenv("TMUX_PATH")

config = load_config()
if not config:
    logger.error("No valid config found.")
    exit(1)


if "version" not in config or int(config["version"]) < 1:
    logger.warn("[WARN] Legacy version of config found. This may cause issues.")


op_mode = config["mode"]
udp_clients = config["udp2raw"]["client"]
udp_servers = config["udp2raw"]["server"]


logger.info("Generating WireGuard config...")
with open("local/{}.conf".format(config["interface"]), "w", encoding='utf-8') as f:
    f.write('''[Interface]
Address = {}
PrivateKey = {}
ListenPort = {}
MTU = {}
'''.format(config["ip"], config["prikey"], config["listen"], config["mtu"]))

    # Generate PostUp
    f.write('''PostUp={} new-session -s tunnel -d 'watch -n 1 --color WG_COLOR_MODE=always wg'
PostUp=sysctl net.core.default_qdisc=fq
PostUp=sysctl net.ipv4.tcp_congestion_control=bbr
'''.format(tmux_path))

    if op_mode in ("s", "m"):
        f.write("PostUp=sysctl net.ipv4.ip_forward=1\n")

    current_dir = os.getcwd()
    bin_tunnel = os.path.join(current_dir, "bin", "udp2raw_amd64")
    bin_speeder = os.path.join(current_dir, "bin", "speederv2_amd64")
    bin_demuxer = os.path.join(current_dir, "bin", "w2u")

    cache_nb_config = []
    cache_config = []
    for client_info in udp_clients:
        speeder_info = client_info["speeder"]
        balancer_info = client_info["demuxer"]

        if balancer_info:
            # ... => Balancer => Tunnels
            cache_nb_config.append("PostUp={} new-window -t tunnel -d '{} -f {} -l {} -t {} -s {}'".format(tmux_path, bin_demuxer, config["listen"], balancer_info["port"], client_info["port"], balancer_info["size"]))

        if speeder_info:
            if balancer_info:
                # WG => Speeder => Balancer => Tunnels
                cache_config.append("PostUp={} new-window -t tunnel -d '{} -c -l127.0.0.1:{} -r 127.0.0.1:{} -f{} --mode 0'".format(tmux_path, bin_speeder, speeder_info["port"], balancer_info["port"], speeder_info["ratio"]))
            else:
                # WG => Speeder => Tunnel
                cache_config.append("PostUp={} new-window -t tunnel -d '{} -c -l127.0.0.1:{} -r 127.0.0.1:{} -f{} --mode 0'".format(tmux_path, bin_speeder, speeder_info["port"], client_info["port"], speeder_info["ratio"]))

        if balancer_info:
            # Generate multiple tunnels
            for offset in range(balancer_info["size"]):
                config_filename = write_tunnel_config("c", "127.0.0.1:{}".format(client_info["port"] + offset), client_info["remote"], client_info["password"])
                filepath = os.path.join(current_dir, "local", "tunnel", config_filename)
                cache_config.append("PostUp={} new-window -t tunnel -d '{} --conf-file {}'".format(tmux_path, bin_tunnel, filepath))
        else:
            config_filename = write_tunnel_config("c", "127.0.0.1:{}".format(client_info["port"]), client_info["remote"], client_info["password"])
            filepath = os.path.join(current_dir, "local", "tunnel", config_filename)
            cache_config.append("PostUp={} new-window -t tunnel -d '{} --conf-file {}'".format(tmux_path, bin_tunnel, filepath))

    for server_info in udp_servers:
        speeder_info = client_info["speeder"]

        if speeder_info:
            # RawTunnel => Speeder => WG
            speeder = server_info["speeder"]
            cache_config.append("PostUp={} new-window -t tunnel -d '{} -s -l127.0.0.1:{} -r 127.0.0.1:{} -f{} --mode 0'".format(tmux_path, bin_speeder, speeder["port"], config["listen"], speeder["ratio"]))

            config_filename = write_tunnel_config("s", "0.0.0.0:{}".format(server_info["port"]), "127.0.0.1:{}".format(speeder["port"]), server_info["password"])
            filepath = os.path.join(current_dir, "local", "tunnel", config_filename)
            cache_config.append("PostUp={} new-window -t tunnel -d '{} --conf-file {}'".format(tmux_path, bin_tunnel, filepath))
        else:
            # RawTunnel => WG
            config_filename = write_tunnel_config("s", "0.0.0.0:{}".format(server_info["port"]), "127.0.0.1:{}".format(config["listen"]), server_info["password"])
            filepath = os.path.join(current_dir, "local", "tunnel", config_filename)
            cache_config.append("PostUp={} new-window -t tunnel -d '{} --conf-file {}'".format(tmux_path, bin_tunnel, filepath))

    # Add sleep interval
    if cache_config:
        for i in range(len(cache_config) - 1):
            cache_config[i] = "{}; sleep 2".format(cache_config[i])
        cache_config.append("")
        f.write('\n'.join(cache_config))

    if cache_nb_config:
        cache_nb_config.append("")
        f.write('\n'.join(cache_nb_config))

    # Generate PostDown
    f.write("PostDown={} kill-session -t tunnel\n".format(tmux_path))

    for peer_info in config["peers"]:
        f.write('''
[Peer]
PublicKey = {}
AllowedIPs = {}
'''.format(peer_info["pubkey"], peer_info["allowed"]))
        if peer_info["endpoint"]:
            client_info = udp_clients[int(peer_info["endpoint"]) - 1]
            speeder_info = client_info["speeder"]
            balancer_info = client_info["demuxer"]

            if speeder_info:
                # WG => Speeder => ...
                f.write("Endpoint = 127.0.0.1:{}\n".format(speeder_info["port"]))
            elif balancer_info:
                # WG => Balancer => ...
                f.write("Endpoint = 127.0.0.1:{}\n".format(balancer_info["port"]))
            else:
                # WG => ...
                f.write("Endpoint = 127.0.0.1:{}\n".format(client_info["port"]))

        if peer_info["keepalive"]:
            f.write("PersistentKeepalive = {}\n".format(peer_info["keepalive"]))

os.system("chmod 600 local/{}.conf".format(config["interface"]))

logger.info("Generating start script...")
with open("start.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -e

sudo cp local/{}.conf /etc/wireguard/
sudo wg-quick up {}
sudo tmux attach-session -t tunnel
'''.format(config["interface"], config["interface"]))


logger.info("Generating stop script...")
with open("stop.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -x
sudo wg-quick down {}
'''.format(config["interface"]))


logger.info("Generating restart script...")
with open("restart.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -x
./stop.sh
./start.sh
''')

logger.info("Generate reload script...")
with open("reload.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -x
sudo cp local/{}.conf /etc/wireguard/
sudo -- bash -c "wg syncconf {} <(wg-quick strip {})"
'''.format(config["interface"], config["interface"], config["interface"]))

    for peer_info in config["peers"]:
        f.write("sudo ip -4 route add {} dev {}\n".format(peer_info["allowed"], config["interface"]))


logger.info('''[Done] Config generated. Before you run start.sh, besure to:
1. Disable SSH Server password login.
2. Enable UFW (or any other firewall)

Safety First.
''')
