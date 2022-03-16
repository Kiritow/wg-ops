# DNS reloader
# WARN: IPv6 style address not supported yet.
import sys
import subprocess
import traceback


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write('python3 reload-dns.py <interface> <peer> <target>\n')
        exit(1)

    interface_name = sys.argv[1]
    peer_pubkey = sys.argv[2]
    target_addr = sys.argv[3]

    # resolve dns
    target_parts = target_addr.split(':')[0]
    target_host = target_parts[0]
    target_port = target_parts[1]
    target_ip = subprocess.check_output(["dig", "+short", target_host]).decode().strip()
    target_endpoint = "{}:{}".format(target_ip, target_port)

    # dump interface
    wg_raw_info = subprocess.check_output(["wg", "show", interface_name, "dump"]).decode().strip().split('\n')
    if not wg_raw_info:
        print('wireguard interface {} not found'.format(interface_name))
        exit(1)

    wg_raw_info = wg_raw_info[1:]
    wg_info = [line.split('\t') for line in wg_raw_info]
    
    wg_info = [x for x in wg_info if x[0] == peer_pubkey]
    if not wg_info:
        print('wireguard interface {} peer {} not found.'.format(interface_name, peer_pubkey))
        exit(1)

    peer_info = wg_info[0]
    peer_endpoint = peer_info[2]
    
    # check and update
    if peer_endpoint != target_endpoint:
        print('Updating endpoint from {} to {}...'.format(peer_endpoint, target_endpoint))
        try:
            subprocess.check_call(["wg", "set", interface_name, "peer", peer_pubkey, "endpoint", target_endpoint])
        except Exception:
            print(traceback.format_exc())
