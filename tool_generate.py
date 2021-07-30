# -*- coding: utf-8 -*-
import os
import uuid
from tool_common import load_config, SimpleLogger


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
-a
'''.format(mode, listen_addr, remote_addr, password))
    return filename


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

    # Generate PostUp
    f.write('''PostUp=/bin/tmux new-session -s tunnel -d 'watch -n 1 --color WG_COLOR_MODE=always wg'
PostUp=sysctl net.core.default_qdisc=fq
PostUp=sysctl net.ipv4.tcp_congestion_control=bbr
''')

    if op_mode in ("s", "m"):
        f.write("PostUp=sysctl net.ipv4.ip_forward=1\n")

    current_dir = os.getcwd()
    path_tunnel = os.path.join(current_dir, "bin", "udp2raw_amd64")
    path_speeder = os.path.join(current_dir, "bin", "speederv2_amd64")

    for info in udp_clients:
        if info["speeder"]["enable"]:
            # WG --> Speeder --> RawTunnel
            speeder = info["speeder"]
            f.write('''PostUp=/bin/tmux new-window -t tunnel -d '{} -c -l127.0.0.1:{} -r 127.0.0.1:{} -f{} --mode 0' \n'''.format(path_speeder, speeder["port"], info["port"], speeder["ratio"]))

        filename = write_tunnel_config("c", "127.0.0.1:{}".format(info["port"]), info["remote"], info["password"])
        filepath = os.path.join(current_dir, "local", "tunnel", filename)
        f.write('''PostUp=/bin/tmux new-window -t tunnel -d '{} --conf-file {}' \n'''.format(path_tunnel, filepath))

    for info in udp_servers:
        if info["speeder"]["enable"]:
            # RawTunnel --> Speeder --> WG
            speeder = info["speeder"]
            f.write('''PostUp=/bin/tmux new-window -t tunnel -d '{} -s -l127.0.0.1:{} -r 127.0.0.1:{} -f{} --mode 0' \n'''.format(path_speeder, speeder["port"], config["listen"], speeder["ratio"]))

            filename = write_tunnel_config("s", "0.0.0.0:{}".format(info["port"]), "127.0.0.1:{}".format(speeder["port"]), info["password"])
            filepath = os.path.join(current_dir, "local", "tunnel", filename)
            f.write('''PostUp=/bin/tmux new-window -t tunnel -d '{} --conf-file {}' \n'''.format(path_tunnel, filepath))
        else:
            # RawTunnel --> WG
            filename = write_tunnel_config("s", "0.0.0.0:{}".format(info["port"]), "127.0.0.1:{}".format(config["listen"]), info["password"])
            filepath = os.path.join(current_dir, "local", "tunnel", filename)
            f.write('''PostUp=/bin/tmux new-window -t tunnel -d '{} --conf-file {}' \n'''.format(path_tunnel, filepath))

    # Generate PostDown
    f.write("PostDown=/bin/tmux kill-session -t tunnel\n")

    for info in config["peers"]:
        f.write('''
[Peer]
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


logger.info('''[Done] Config generated. Before you run start.sh, besure to:
1. Disable SSH Server password login.
2. Enable UFW (or any other firewall)

Safety First.
''')
