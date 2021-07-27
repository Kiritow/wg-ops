# -*- coding: utf-8 -*-
import os
from tool_common import load_config, SimpleLogger


logger = SimpleLogger()


config = load_config()
if not config:
    logger.error("No valid config found.")
    exit(1)


if "version" not in config or int(config["version"]) < 1:
    logger.warn("[WARN] Legacy version of config found. This may cause issues.")


op_mode = config["mode"]
udp_clients = config["udp2raw"]["client"]
udp_servers = config["udp2raw"]["server"]


logger.info("Generating wireguard config...")
with open("local/{}.conf".format(config["interface"]), "w", encoding='utf-8') as f:
    f.write('''[Interface]
Address = {}
PrivateKey = {}
ListenPort = {}
MTU = {}
'''.format(config["ip"], config["prikey"], config["listen"], config["mtu"]))
    
    for info in config["peers"]:
        f.write('''[Peer]
PublicKey = {}
AllowedIPs = {}
'''.format(info["pubkey"], info["allowed"]))
        if info["endpoint"]:
            udp_info = udp_clients[int(info["endpoint"]) - 1]
            if udp_info["speeder"]["enable"]:
                # WG --> Speeder
                f.write("Endpoint = 127.0.0.1:{}\n".format(udp_info["speeder"]["port"]))
            else:
                # WG --> Tunnel
                f.write("Endpoint = 127.0.0.1:{}\n".format(udp_info["port"]))
        if info["keepalive"]:
            f.write("PersistentKeepalive = {}\n".format(info["keepalive"]))

os.system("chmod 600 local/{}.conf".format(config["interface"]))

logger.info("Generating start script...")
with open("start.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -e

cp local/{}.conf /etc/wireguard/
tmux new-session -s tunnel -d 'watch -n 1 wg'
'''.format(config["interface"]))
    for info in udp_clients:
        if info["speeder"]["enable"]:
            # WG --> Speeder --> RawTunnel
            speeder = info["speeder"]
            f.write('''tmux new-window -t tunnel -d 'bin/speederv2_amd64 -c -l127.0.0.1:{} -r 127.0.0.1:{} -f{} --mode 0' \n'''.format(speeder["port"], info["port"], speeder["ratio"]))

        f.write('''tmux new-window -t tunnel -d 'bin/udp2raw_amd64 -c -l127.0.0.1:{} -r{} -k "{}" --raw-mode faketcp -a' \n'''.format(info["port"], info["remote"], info["password"]))

    for info in udp_servers:
        if info["speeder"]["enable"]:
            # RawTunnel --> Speeder --> WG
            speeder = info["speeder"]
            f.write('''tmux new-window -t tunnel -d 'bin/speederv2_amd64 -s -l127.0.0.1:{} -r 127.0.0.1:{} -f{} --mode 0' \n'''.format(speeder["port"], config["listen"], speeder["ratio"]))
            f.write('''tmux new-window -t tunnel -d 'bin/udp2raw_amd64 -s -l0.0.0.0:{} -r 127.0.0.1:{} -k "{}" --raw-mode faketcp -a' \n'''.format(info["port"], speeder["port"], info["password"]))
        else:
            # RawTunnel --> WG
            f.write('''tmux new-window -t tunnel -d 'bin/udp2raw_amd64 -s -l0.0.0.0:{} -r 127.0.0.1:{} -k "{}" --raw-mode faketcp -a' \n'''.format(info["port"], config["listen"], info["password"]))

    # Enable BBR
    f.write("sysctl net.core.default_qdisc=fq\n")
    f.write("sysctl net.ipv4.tcp_congestion_control=bbr\n")

    if op_mode in ("s", "m"):
        f.write("sysctl net.ipv4.ip_forward=1\n")

    f.write('''wg-quick up {}
tmux attach-session -t tunnel
'''.format(config["interface"]))


logger.info("Generating stop script...")
with open("stop.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -x
wg-quick down {}
tmux kill-session -t tunnel
'''.format(config["interface"]))


logger.info("Generating restart script...")
with open("restart.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -x
./stop.sh
./start.sh
''')


logger.info('''[Done] Config generated. Before you run start.sh, besure to:
1. Disable SSH Server password login.
2. Enable UFW (or any other firewall)

Safety First.
''')
