import sys
import json
import subprocess


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write('python3 get-gateway.py <network>\n')
        exit(1)

    network_name = sys.argv[1]
    output = subprocess.check_output(["podman", "network", "inspect", network_name])

    j = json.loads(output)
    print(j[0]["plugins"][0]["ipam"]["ranges"][0][0]["gateway"])
