import sys
import socket
import subprocess
import traceback


if __name__ == "__main__":
    output = subprocess.check_output(["ip", "route"]).decode()
    test_ip = '8.8.8.8'
    for line in output.split('\n'):
        if line.startswith('default'):
            test_ip = line.split(' ')[2]
            break

    sys.stderr.write('Try get lan ip with {}...\n'.format(test_ip))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        s.connect((test_ip, 53))

        print(s.getsockname()[0])
    except Exception:
        sys.stderr.write("{}\n".format(traceback.format_exc()))
        print('127.0.0.1')
