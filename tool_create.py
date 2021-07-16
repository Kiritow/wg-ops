# -*- coding: utf-8 -*-
import os
import json
import traceback

try:
    with open("config.json") as f:
        content = f.read()
    config = json.loads(content)
    print("[WARN] Found a valid config. Creation of server is skipped.")
    exit(0)
except Exception:
    print(traceback.format_exc())

op_mode = input("What will this node act as? (C)lient [S]erver [M]ixed: ").strip().lower()
if not op_mode:
    print("Default to client mode.")
    op_mode = "c"

if op_mode not in ("c", "s", "m"):
    print("Invalid node mode. Please try again.")
    exit(1)

udp2raw_config = {
    "server": [],
    "client": []
}

if op_mode in ("s", "m"):
    print("====== Configuring udp2raw server ======")

    while True:
        print("====== Adding UDP2RAW Server {} ======".format(len(udp2raw_config["server"]) + 1))

        while True:
            udp_server_port = input("Please select an Internet-Facing port for incoming udp2raw connection: ").strip()
            if not udp_server_port:
                print("A udp2raw listen port is required. Try again.")
                continue
            break

        while True:
            udp_server_password = input("Please input udp2raw tunnel password: ").strip()
            if not udp_server_password:
                print("A udp2raw tunnel password is required. Try again.")
                continue
            break

        udp2raw_config["server"].append({
            "port": udp_server_port,
            "password": udp_server_password
        })

        if not input("Add more udp2raw server? (Keep empty to finish)").strip():
            break


if op_mode in ("c", "m"):
    print("====== Configuring udp2raw client ======")

    while True:
        print("====== Adding UDP2RAW Client {} ======".format(len(udp2raw_config["client"]) + 1))

        while True:
            udp_server_address = input("Please input remote node internet-facing udp2raw ip:port : ").strip()
            if not udp_server_address:
                print("A udp2raw remote server information is required. Try again.")
                continue
            break

        while True:
            udp_server_password = input("Please input udp2raw tunnel password: ").strip()
            if not udp_server_password:
                print("A udp2raw tunnel password is required. Try again.")
                continue
            break

        udp2raw_config["client"].append({
            "remote": udp_server_address,
            "password": udp_server_password,
            "port": 28150 + len(udp2raw_config["client"])
        })
    
        if not input("Add more udp2raw client? (Keep empty to finish)").strip():
            break


wg_prik = os.getenv("WG_MYPRIK")
wg_pubk = os.getenv("WG_MYPUBK")
wg_mtu = "1000"
wg_public_ip = os.getenv("WG_PUBLICIP")

print('''

====== Your Wireguard Public Key ======

{}

======= Your Public IP Address ========

{}

=======================================

'''.format(wg_pubk, wg_public_ip))

ifname = input("Input new wireguard interface name (wg0):").strip() or "wg0"
listen_port = input("Input new wireguard listen port (51820): ").strip() or "51820"
while True:
    ifip = input("Input wireguard interface ip (Example: 10.0.0.1): ").strip()
    if not ifip:
        print("You MUST set a valid wireguard interface IP. Try Again.")
        continue
    break

peers = []

while True:
    print("====== Adding Peer {} ======".format(len(peers) + 1))
    while True:
        peer_pubk = input("Enter Wireguard Peer Public Key: ").strip()
        if not peer_pubk:
            print("A public key is required. Try Again.")
            continue
        break
    while True:
        peer_allowed = input("Enter Wireguard Peer AllowedIPs (CIDR, Example: 10.0.0.0/24): ").strip()
        if not peer_allowed:
            print("Peer allowed ips required. Try Again.")
            continue
        break

    print(">>> Choose from following udp2raw clients <<<")
    for index, client_info in enumerate(udp2raw_config["client"]):
        print("[{}] UDP2Raw Tunnel to Remote {}".format(index + 1, client_info["remote"]))

    peer_endpoint = input("Enter Wireguard Peer Endpoint (ID from tunnel list, keep empty on server side): ").strip()
    if peer_endpoint:
        peer_keepalive = input("Enter Wireguard Peer Keep Alive seconds: ").strip()
    else:
        peer_keepalive = ""

    peers.append({
        "pubkey": peer_pubk,
        "allowed": peer_allowed,
        "endpoint": peer_endpoint,
        "keepalive": peer_keepalive
    })

    if not input("Add more peers? (Keep empty to finish)").strip():
        break

print("Saving to local config...")

config = {
    "mode": op_mode,
    "pubkey": wg_pubk,
    "prikey": wg_prik,
    "mtu": wg_mtu,
    "interface": ifname,
    "ip": ifip,
    "listen": listen_port,
    "peers": peers,
    "udp2raw": udp2raw_config
}

with open("config.json", "w") as f:
    f.write(json.dumps(config, ensure_ascii=False))
