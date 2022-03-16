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
    target_parts = target_addr.split(':')
    target_host = target_parts[0]
    target_port = target_parts[1]
    target_ip = subprocess.check_output(["dig", "+short", target_host]).decode().strip()
    if not target_ip:
        sys.stderr.write('unable to resolve domain: {}\n'.format(target_host))
        exit(1)

    target_endpoint = "{}:{}".format(target_ip, target_port)

    # dump interface
    wg_raw_info = subprocess.check_output(["wg", "show", interface_name, "dump"]).decode().strip().split('\n')
    if not wg_raw_info:
        sys.stderr.write('wireguard interface {} not found.\n'.format(interface_name))
        exit(1)

    wg_raw_info = wg_raw_info[1:]
    wg_info = [line.split('\t') for line in wg_raw_info]
    
    wg_info = [x for x in wg_info if x[0] == peer_pubkey]
    if not wg_info:
        sys.stderr.write('wireguard interface {} peer {} not found.\n'.format(interface_name, peer_pubkey))
        exit(1)

    peer_info = wg_info[0]
    peer_endpoint = peer_info[2]
    
    # check and update
    if peer_endpoint != target_endpoint:
        print('Updating endpoint from {} to {}...'.format(peer_endpoint, target_endpoint))
        try:
            subprocess.check_call(["wg", "set", interface_name, "peer", peer_pubkey, "endpoint", target_endpoint])
        except Exception:
            sys.stderr.write(traceback.format_exc())
    else:
        print('Endpoint matches: {}, skipping update.'.format(peer_endpoint))
