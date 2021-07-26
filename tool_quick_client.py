# -*- coding: utf-8 -*-
import os
import getpass
from tool_common import load_config, save_config, base64_to_json


config = load_config()

if config:
    print("Valid config found. Creation of server is skipped.")
    exit(0)


print("No valid config found, creating a default one...")

ifname = input("Input new wireguard interface name (wg0):").strip() or "wg0"
listen_port = input("Input new wireguard listen port (51820): ").strip() or "51820"
while True:
    ifip = input("Input wireguard interface ip (Example: 10.0.0.1)\n> ").strip()
    if not ifip:
        print("You MUST set a valid wireguard interface IP. Try Again.")
        continue
    break


paste_config = {}
while True:
    paste_temp = input("Paste Quick Setup: ").strip()
    if not paste_temp.startswith("#QCS#"):
        print("Config not valid. Try again.")
        continue

    paste_config = base64_to_json(paste_temp.replace("#QCS#", ""))
    print("Config imported. Server: {} with public key: {}".format(paste_config["udp2raw_client"]["remote"], paste_config["server_pubkey"]))
    break


while True:
    udp_server_password = getpass.getpass('Tunnel Password: ').strip()
    if not udp_server_password:
        print("For security reasons, a udp2raw tunnel password is required. Try again.")
        continue

    if udp_server_password != getpass.getpass('Confirm Tunnel Password: ').strip():
        print("Password mismatch. Try again.")
        continue
    break
paste_config["udp2raw_client"]["password"] = udp_server_password


if paste_config["suggest_allowed"]:
    peer_allowed = input("Enter Wireguard Peer AllowedIPs (CIDR, Example: 10.0.0.0/24, default to {})\n> ".format(paste_config["suggest_allowed"])).strip()
    if not peer_allowed:
        peer_allowed = paste_config["suggest_allowed"]
else:
    while True:
        peer_allowed = input("Enter Wireguard Peer AllowedIPs (CIDR, Example: 10.0.0.0/24)\n> ").strip()
        if not peer_allowed:
            print("Peer allowed ips required. Try Again.")
            continue
        break


peer_keepalive = input("Enter Wireguard Peer Keep Alive seconds (default to 30): ").strip() or "30"


# Generate Config
config = {
    "version": 1,
    "mode": "c",
    "prikey": os.getenv("WG_MYPRIK"),
    "pubkey": os.getenv("WG_MYPUBK"),
    "mtu": "1000",
    "interface": ifname,
    "ip": ifip,
    "listen": listen_port,
    "peers": [{
        "pubkey": paste_config["server_pubkey"],
        "allowed": peer_allowed,
        "endpoint": "1",
        "keepalive": peer_keepalive
    }],
    "udp2raw": [{
        "client": [paste_config["udp2raw_client"]],
        "server": []
    }]
}

print("Saving config...")
save_config(config)

print('''

====== Your Wireguard Public Key ======

{}

====== Your WireGuard IP Address ======

{}

=======================================

'''.format(os.getenv("WG_MYPUBK"), ifip))
