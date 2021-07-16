# -*- coding: utf-8 -*-
import os
import json
import traceback

try:
    with open("config.json") as f:
        content = f.read()
    config = json.loads(content)
except Exception:
    print(traceback.format_exc())
    print("[ERROR] No valid config found.")

op_mode = config["mode"]
udp_clients = config["udp2raw"]["client"]
udp_servers = config["udp2raw"]["server"]

print("Generating wireguard config...")
with open("{}.conf".format(config["interface"]), "w", encoding='utf-8') as f:
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
            f.write("Endpoint = 127.0.0.1:{}\n".format(udp_clients[int(info["endpoint"]) - 1]["port"]))
        if info["keepalive"]:
            f.write("PersistentKeepalive = {}".format(info["keepalive"]))

os.system("chmod 600 {}.conf".format(config["interface"]))

print("Generating start script...")
with open("start.sh", "w", encoding='utf-8') as f:
    f.write('''#!/bin/bash
set -e

cp {}.conf /etc/wireguard/
tmux new-session -s tunnel -d
'''.format(config["interface"]))
    for info in udp_clients:
        f.write('''tmux new-window -t tunnel -d 'bin/udp2raw_amd64 -c -l127.0.0.1:{} -r{} -k "{}" --raw-mode faketcp -a' \n'''.format(info["port"], info["remote"], info["password"]))

    for info in udp_servers:
        f.write('''tmux new-window -t tunnel -d 'bin/udp2raw_amd64 -s -l0.0.0.0:{} -r 127.0.0.1:{} -k "{}" --raw-mode faketcp -a' \n'''.format(info["port"], config["listen"], info["password"]))

    if op_mode in ("s", "m"):
        f.write("sysctl net.ipv4.ip_forward=1\n")

    f.write('''wg-quick up {}
tmux attach-session -t tunnel
'''.format(config["interface"]))

print('''[OK] Config generated. Before you run start.sh, besure to:
1. Disable SSH Server password login.
2. Enable UFW (or any other firewall)

Safety First.
''')
