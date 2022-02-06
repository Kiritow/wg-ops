import sys
import json
import subprocess


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.stderr.write('python3 get-ip.py <network> <container>\n')
        exit(1)

    network_name = sys.argv[1]
    container_name = sys.argv[2]
    output = subprocess.check_output(["podman", "inspect", container_name])

    j = json.loads(output)
    print(j[0]["NetworkSettings"]["Networks"][network_name]["IPAddress"])
