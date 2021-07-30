# -*- coding: utf-8 -*-
import os
import getpass
from tool_common import load_config, save_config, SimpleLogger, json_to_base64


config = load_config()
if config:
    print("Valid config found. Creation of server is skipped.")
    exit(0)
else:
    print("No config found. Start creating interactively.")

print("====== Choose Role ======")

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
            udp_server_password = getpass.getpass('Tunnel Password: ').strip()
            if not udp_server_password:
                print("For security reasons, a udp2raw tunnel password is required. Try again.")
                continue

            if udp_server_password != getpass.getpass('Confirm Tunnel Password: ').strip():
                print("Password mismatch. Try again.")
                continue

            break

        is_enable_speeder = input("Enable UDP Speeder for this tunnel? [y/N]: ").strip()
        if is_enable_speeder and is_enable_speeder.lower() in ('y', 'yes'):
            speeder_ratio = input("Enter UDP Speeder Ratio (default to 20:10. Use 2:4 for gaming usage): ").strip() or "20:10"
            speeder_info = {
                "enable": True,
                "port": 27100 + len(udp2raw_config["server"]),
                "ratio": speeder_ratio
            }
        else:
            speeder_info = {
                "enable": False
            }

        udp2raw_config["server"].append({
            "port": udp_server_port,
            "password": udp_server_password,
            "speeder": speeder_info
        })

        if not input("Add more udp2raw server? (Keep empty to finish): ").strip():
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
            udp_server_password = getpass.getpass('Tunnel Password: ').strip()
            if not udp_server_password:
                print("A udp2raw tunnel password is required. Try again.")
                continue

            if udp_server_password != getpass.getpass('Confirm Tunnel Password: ').strip():
                print("Password mismatch. Try again.")
                continue

            break

        is_enable_speeder = input("Enable UDP Speeder for this tunnel? [y/N]: ").strip()
        if is_enable_speeder and is_enable_speeder.lower() in ('y', 'yes'):
            speeder_ratio = input("Enter UDP Speeder Ratio (default to 20:10. Use 2:4 for gaming usage): ").strip() or "20:10"
            speeder_info = {
                "enable": True,
                "port": 28100 + len(udp2raw_config["server"]),
                "ratio": speeder_ratio
            }
        else:
            speeder_info = {
                "enable": False
            }

        udp2raw_config["client"].append({
            "remote": udp_server_address,
            "password": udp_server_password,
            "port": 29100 + len(udp2raw_config["client"]),
            "speeder": speeder_info
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
    ifip = input("Input wireguard interface ip (Example: 10.0.0.1)\n> ").strip()
    if not ifip:
        print("You MUST set a valid wireguard interface IP. Try Again.")
        continue
    break


print("Saving config...")
config = {
    "version": 1,
    "mode": op_mode,
    "pubkey": wg_pubk,
    "prikey": wg_prik,
    "mtu": wg_mtu,
    "interface": ifname,
    "ip": ifip,
    "listen": listen_port,
    "peers": [],
    "udp2raw": udp2raw_config
}
save_config(config)


if op_mode in ("s", "m"):
    if ifip.endswith(".1"):
        suggest_allowed = "{}.0/24".format('.'.join(ifip.split('.')[:-1]))
    else:
        suggest_allowed = ifip

    print("===== Quick Import =====")
    for info in udp2raw_config["server"]:
        target_quick_config = {
            "udp2raw_client": {
                "remote": "{}:{}".format(wg_public_ip, info["port"]),
                "password": "",
                "port": "29100",
                "speeder": info["speeder"]
            },
            "server_pubkey": wg_pubk,
            "suggest_allowed": suggest_allowed
        }

        print("Connect to this server via tunnel at port {}: (credential excluded) \n".format(info["port"]))
        print("#QCS#{}\n".format(json_to_base64(target_quick_config)))


# Configure Peer

while True:
    print("====== Adding Peer {} ======".format(len(config["peers"]) + 1))
    while True:
        peer_pubk = input("Enter Wireguard Peer Public Key: ").strip()
        if not peer_pubk:
            print("A public key is required. Try Again.")
            continue
        break
    while True:
        peer_allowed = input("Enter Wireguard Peer AllowedIPs (CIDR, Example: 10.0.0.0/24)\n> ").strip()
        if not peer_allowed:
            print("Peer allowed ips required. Try Again.")
            continue
        break

    if config["udp2raw"]["client"]:
        print(">>> Choose from following udp2raw clients <<<")
        for index, client_info in enumerate(config["udp2raw"]["client"]):
            print("[{}] UDP2Raw Tunnel to Remote {}".format(index + 1, client_info["remote"]))

        peer_endpoint = input("Enter Wireguard Peer Endpoint (ID from list, default to 1): ").strip() or "1"
        peer_keepalive = input("Enter Wireguard Peer Keep Alive seconds (default to 30): ").strip() or "30"
    else:
        peer_endpoint = ""
        peer_keepalive = ""

    config["peers"].append({
        "pubkey": peer_pubk,
        "allowed": peer_allowed,
        "endpoint": peer_endpoint,
        "keepalive": peer_keepalive
    })

    print("Saving config...")
    save_config(config)

    if not input("Add more peers? (Keep empty to finish)").strip():
        break
