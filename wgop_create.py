# -*- coding: utf-8 -*-
import os
import getpass
from wgop_common import load_config, save_config, get_randpass, get_quick_config
from wgop_common import UConfigController


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


ucontrol = UConfigController()


if op_mode in ("s", "m"):
    print("====== Configuring udp2raw server ======")

    while True:
        print("====== Adding UDP2RAW Server #{} ======".format(len(ucontrol.udp2raw_config["server"]) + 1))

        while True:
            udp_server_port = input("Please select an Internet-Facing port for incoming udp2raw connection: ").strip()
            if not udp_server_port:
                print("A udp2raw listen port is required. Try again.")
                continue
            break

        while True:
            udp_server_password = getpass.getpass('Tunnel Password: (Keep empty to generate one)').strip()
            if not udp_server_password:
                udp_server_password = get_randpass(15)
                print("Generated Password: {}".format(udp_server_password))
                break

            if udp_server_password != getpass.getpass('Confirm Tunnel Password: ').strip():
                print("Password mismatch. Try again.")
                continue

            break

        is_enable_speeder = input("Enable UDP Speeder for this tunnel? [y/N]: ").strip()
        if is_enable_speeder and is_enable_speeder.lower() in ('y', 'yes'):
            speeder_ratio = input("Enter UDP Speeder Ratio (default to 20:10. Use 2:4 for gaming usage): ").strip() or "20:10"
            speeder_info = ucontrol.new_server_speeder(None, speeder_ratio)
        else:
            speeder_info = None

        ucontrol.add_server(udp_server_port, udp_server_password, speeder_info)

        if not input("Add more udp2raw server? (Keep empty to finish): ").strip():
            break


if op_mode in ("c", "m"):
    print("====== Configuring udp2raw client ======")

    while True:
        print("====== Adding UDP2RAW Client {} ======".format(len(ucontrol.udp2raw_config["client"]) + 1))

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
            speeder_info = ucontrol.new_client_speeder(None, speeder_ratio)
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

        ucontrol.add_client(udp_server_address, udp_server_password, None, speeder_info, balancer_info)

        if not input("Add more udp2raw client? (Keep empty to finish)").strip():
            break


wg_prik = os.getenv("WG_MYPRIK")
wg_pubk = os.getenv("WG_MYPUBK")
wg_mtu = "1000"
wg_public_ip = os.getenv("WG_PUBLICIP")

print('''

====== Your WireGuard Public Key ======

{}

======= Your Public IP Address ========

{}

=======================================

'''.format(wg_pubk, wg_public_ip))

ifname = input("Input new WireGuard interface name (wg0):").strip() or "wg0"
listen_port = input("Input new WireGuard listen port (51820): ").strip() or "51820"
while True:
    ifip = input("Input WireGuard interface ip (Example: 10.0.0.1)\n> ").strip()
    if not ifip:
        print("You MUST set a valid WireGuard interface IP. Try Again.")
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
    "udp2raw": ucontrol.udp2raw_config
}
save_config(config)


# Display Quick Config
if op_mode in ("s", "m"):
    print("===== Quick Import =====")
    quicks = get_quick_config(config, wg_public_ip)
    for quick_info in quicks:
        print("Connect to this server via tunnel at port {}: (credential included)\n{}\n".format(quick_info["port"], quick_info["qcs"]))


# Configure Peer
while True:
    print("====== Adding Peer {} ======".format(len(config["peers"]) + 1))
    while True:
        peer_pubk = input("Enter WireGuard Peer Public Key: ").strip()
        if not peer_pubk:
            print("A public key is required. Try Again.")
            continue
        break
    while True:
        peer_allowed = input("Enter WireGuard Peer AllowedIPs (CIDR, Example: 10.0.0.0/24)\n> ").strip()
        if not peer_allowed:
            print("Peer allowed ips required. Try Again.")
            continue
        break

    if ucontrol.udp2raw_config["client"]:
        print(">>> Choose from following udp2raw clients <<<")
        for index, client_info in enumerate(ucontrol.udp2raw_config["client"]):
            speeder_info = client_info["speeder"]
            balancer_info = client_info["demuxer"]

            print("[{}] {} {} {}".format(index + 1, client_info["remote"], 
                "SpeederRatio: {}".format(speeder_info["ratio"]) if speeder_info else "",
                "Load-Balanced over {} tunnels".format(balancer_info["size"]) if balancer_info else ""
            ))

        peer_endpoint = input("Enter WireGuard Peer Endpoint (ID from list, default to 1): ").strip() or "1"
        peer_keepalive = input("Enter WireGuard Peer Keep Alive seconds (default to 30): ").strip() or "30"
    else:
        peer_endpoint = ""
        peer_keepalive = ""

    peer_name = input("Enter Peer name (optional): ").strip() or ""

    config["peers"].append({
        "pubkey": peer_pubk,
        "allowed": peer_allowed,
        "endpoint": peer_endpoint,
        "keepalive": peer_keepalive,
        "name": peer_name,
    })

    print("Saving config...")
    save_config(config)

    if not input("Add more peers? (Keep empty to finish)").strip():
        break
