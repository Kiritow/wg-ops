# -*- coding: utf-8 -*-
import os
from wgop_common import load_config, save_config, base64_to_json
from wgop_common import UConfigController


config = load_config()

if config:
    print("Valid config found. Creation of server is skipped.")
    exit(0)


print("No valid config found, creating a default one...")

ifname = input("Input new WireGuard interface name (wg0): ").strip() or "wg0"
listen_port = input("Input new WireGuard listen port (51820): ").strip() or "51820"
while True:
    ifip = input("Input WireGuard interface ip (Example: 10.0.0.1)\n> ").strip()
    if not ifip:
        print("You MUST set a valid WireGuard interface IP. Try Again.")
        continue
    break

ucontrol = UConfigController()

paste_config = {}
while True:
    paste_temp = input("Paste Quick Setup: ").strip()
    if not paste_temp.startswith("#QCS#"):
        print("Config not valid. Try again.")
        continue

    paste_config = base64_to_json(paste_temp.replace("#QCS#", ""))
    print("Config imported. Server: {} with public key: {}{}".format(
        paste_config["remote"], paste_config["pubkey"],
        " and speeders enabled" if paste_config["ratio"] else ""))
    break


if paste_config["ratio"]:
    speeder_info = ucontrol.new_client_speeder(None, paste_config["ratio"])
else:
    speeder_info = None


is_enable_balance = input("Enable Load Balance? [y/N]: ").strip()
if is_enable_balance and is_enable_balance.lower() in ('y', 'yes'):
    balance_count = input("Enter Balance Underlay Connection counts (default to 10): ").strip() or "10"
    balance_count = int(balance_count)

    if balance_count > 1:
        balancer_info = ucontrol.new_demuxer(None, balance_count)
    else:
        print("[WARN] Only one target, skipped balancer creation.")
        balancer_info = None
else:
    balancer_info = None


ucontrol.add_client(paste_config["remote"], paste_config["password"], None, speeder_info, balancer_info, no_hash=True)


if paste_config["allowed"]:
    peer_allowed = input("Enter WireGuard Peer AllowedIPs (CIDR, Example: 10.0.0.0/24, default to {})\n> ".format(paste_config["allowed"])).strip()
    if not peer_allowed:
        peer_allowed = paste_config["allowed"]
else:
    while True:
        peer_allowed = input("Enter WireGuard Peer AllowedIPs (CIDR, Example: 10.0.0.0/24)\n> ").strip()
        if not peer_allowed:
            print("Peer allowed ips required. Try Again.")
            continue
        break


peer_keepalive = input("Enter WireGuard Peer Keep Alive seconds (default to 30): ").strip() or "30"


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
        "pubkey": paste_config["pubkey"],
        "allowed": peer_allowed,
        "endpoint": "1",
        "keepalive": peer_keepalive
    }],
    "udp2raw": ucontrol.udp2raw_config
}

print("Saving config...")
save_config(config)

print('''

====== Your WireGuard Public Key ======

{}

====== Your WireGuard IP Address ======

{}

=======================================

'''.format(os.getenv("WG_MYPUBK"), ifip))
