import sys
import subprocess
import sqlite3


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.stderr.write('python3 collect-metrics.py <interface> <filepath>\n')
        exit(1)

    interface_name = sys.argv[1]
    file_path = sys.argv[2]

    wg_raw_info = subprocess.check_output(["wg", "show", interface_name, "dump"]).decode().strip().split('\n')
    if not wg_raw_info:
        sys.stderr.write('wireguard interface {} not found.\n'.format(interface_name))
        exit(1)

    wg_raw_info = wg_raw_info[1:]
    wg_info = [line.split('\t') for line in wg_raw_info]

    db = sqlite3.connect(file_path)
    db.row_factory = sqlite3.Row
    conn = db.cursor()
    conn.execute("select count(1) as n from sqlite_master where type='table' and name='t_monitor'")
    if not conn.fetchall()[0]['n']:
        print('Table `t_monitor` not exists. Creating one...')
        conn.execute('''
CREATE TABLE t_monitor (
    f_interface varchar(64) not null,
    f_peer_key varchar(64) not null,
    f_endpoint varchar(256) not null default '',
    f_rx_bytes bigint(20) not null default 0,
    f_tx_bytes bigint(20) not null default 0,
    f_last_handshake timestamp,
    f_create_time timestamp not null default current_timestamp
)
''')
        conn.execute("CREATE INDEX k_idx_ctime on t_monitor (f_create_time)")
        db.commit()
    
    for info_parts in wg_info:
        conn.execute('insert into t_monitor(f_interface, f_peer_key, f_endpoint, f_rx_bytes, f_tx_bytes, f_last_handshake) values (?, ?, ?, ?, ?, ?)',
            (interface_name, info_parts[0], info_parts[2], info_parts[5], info_parts[6], info_parts[4]))

    db.commit()
