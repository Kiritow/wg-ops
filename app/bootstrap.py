import os
import sys
import json
import uuid
import time
import subprocess


def write_progress(content):
    sys.stdout.write("\033[2K\r{}".format(content))
    time.sleep(0.1)


def write_finish(content):
    sys.stdout.write("\033[2K\r{}\n".format(content))


def add_runner(runner_pool, content):
    runner_id = str(uuid.uuid4())

    with open("/root/runner/{}.sh".format(runner_id), "w") as f:
        f.write(content)

    subprocess.check_call(["chmod", "+x", "/root/runner/{}.sh".format(runner_id)])
    runner_pool.append(runner_id)


def run_cmd(args):
    write_progress("[Run] {}".format(' '.join(args)))
    subprocess.check_call(args)


if __name__ == "__main__":
    gateway_ip = os.getenv('GATEWAY_IP')
    wg_port = os.getenv('WG_PORT')

    print('gateway ip is {}'.format(gateway_ip))

    print('Adding hostname...')
    with open('/etc/hosts', 'a') as f:
        f.write('\n{} wgop.gateway\n'.format(gateway_ip))

    runners = []

    print('Reading bootstrap.json...')
    with open('/root/conf/bootstrap.json') as f:
        config = f.read()
        config = json.loads(config)

    for idx, info in enumerate(config):
        write_progress('Loading {} of {} parts, type: {}...'.format(idx + 1, len(config), info['type']))

        if info['type'] == 'mux':
            add_runner(runners, '''#!/bin/bash
exec /root/bin/mux -l {} -t {} -s {}
'''.format(info['listen'], info['forward'], info['size']))

        elif info['type'] == 'udp2raw-client':
            with open('/root/conf/{}.conf'.format(info['id']), 'w') as f:
                f.write('-c\n-l 0.0.0.0:{}\n-r {}\n-k {}\n--raw-mode faketcp'.format(info['listen'], info['remote'], info['password']))

            with open('/root/conf/{}-ipt.conf'.format(info['id']), 'w') as f:
                f.write('-c\n-l 0.0.0.0:{}\n-r {}\n-k {}\n--raw-mode faketcp\n-g'.format(info['listen'], info['remote'], info['password']))

            add_runner(runners, '''#!/bin/bash
exec /root/bin/udp2raw_amd64 --conf-file /root/conf/{}.conf
'''.format(info['id']))
        
        elif info['type'] == 'udp2raw-server':
            with open('/root/conf/{}.conf'.format(info['id']), 'w') as f:
                f.write('-s\n-l 0.0.0.0:{}\n-r {}:{}\n-k {}\n--raw-mode faketcp'.format(info['listen'], gateway_ip, wg_port, info['password']))

            with open('/root/conf/{}-ipt.conf'.format(info['id']), 'w') as f:
                f.write('-s\n-l 0.0.0.0:{}\n-r {}:{}\n-k {}\n--raw-mode faketcp\n-g'.format(info['listen'], gateway_ip, wg_port, info['password']))

            add_runner(runners, '''#!/bin/bash
exec /root/bin/udp2raw_amd64 --conf-file /root/conf/{}.conf
'''.format(info['id']))

        elif info['type'] == 'gost-client':
            add_runner(runners, '''#!/bin/bash
exec /root/bin/gost -L udp://:{} -F relay+tls://{}
'''.format(info['listen'], info['remote']))

        elif info['type'] == 'gost-server':
            add_runner(runners, '''#!/bin/bash
exec /root/bin/gost -L=relay+tls://:{}/{}:{}
'''.format(info['listen'], gateway_ip, wg_port))

        elif info['type'] == 'trojan-client':
            if ':' in info['remote']:
                remote_parts = info['remote'].split(':')
                remote_host = remote_parts[0]
                remote_port = int(remote_parts[1])
            else:
                remote_host = info['remote']
                remote_port = 443

            jconfig = {
                "run_type": "forward",
                "local_addr": "0.0.0.0",
                "local_port": int(info['listen']),
                "remote_addr": remote_host,
                "remote_port": remote_port,
                "target_addr": "wgop.gateway",
                "target_port": int(info['target']),
                "password": [info['password']],
                "ssl": {}
            }

            if info['sni']:
                jconfig["ssl"]["sni"] = info['sni']
            else:
                jconfig["ssl"]["sni"] = remote_host

            config_id = str(uuid.uuid4())
            with open("/root/conf/{}.json".format(config_id), "w") as f:
                f.write(json.dumps(jconfig))
            
            add_runner(runners, '''#!/bin/bash
exec /root/bin/trojan-go -config /root/conf/{}.json
'''.format(config_id))

        elif info['type'] == 'trojan-server':
            jconfig = {
                "run_type": "server",
                "local_addr": "0.0.0.0",
                "local_port": int(info['listen']),
                "remote_addr": "127.0.0.1",
                "remote_port": 80,
                "password": [info['password']],
                "ssl": {
                    "cert": "/root/ssl/{}.cert".format(info['cert']),
                    "key": "/root/ssl/{}.key".format(info['cert']),
                    "fallback_port": 80
                }
            }

            config_id = str(uuid.uuid4())
            with open("/root/conf/{}.json".format(config_id), "w") as f:
                f.write(json.dumps(jconfig))

            add_runner(runners, '''#!/bin/bash
systemctl start nginx
exec /root/bin/trojan-go -config /root/conf/{}.json
'''.format(config_id))
        else:
            write_finish('Unknown type: {}'.format(info['type']))

    write_finish('{} parts loaded.'.format(len(config)))

    print('Adding service template...')
    with open("/lib/systemd/system/wg-ops-runner@.service", "w") as f:
        f.write('''[Unit]
Description=WireGuard Ops Serivce Runner for %I

[Service]
Type=simple
ExecStart=/bin/bash /root/runner/%i.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
''')

    run_cmd(["systemctl", "daemon-reload"])

    for idx, runner_id in enumerate(runners):
        write_progress("Starting runner {} of {}...".format(idx + 1, len(runners)))
        run_cmd(["systemctl", "start", "wg-ops-runner@{}".format(runner_id)])

    write_finish('{} runner started.'.format(len(runners)))

    print('Bootstrap finished.')
