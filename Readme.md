# WireGuard Ops

A group of Interactive bash scripts for [WireGuard](https://github.com/WireGuard/wireguard-go) over [udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel), with optional [UDPSpeeder](https://github.com/wangyu-/UDPspeeder) support.

## Basic Usage

1. Run `install.sh`. (May prompt sudo)

2. Write a valid WireGuard config file, with supported extension tags.

3. Run `python3 generate.py` to convert extension tags into config lines.

Start as service: `systemctl start wg-quick@wg0`

Start service on system start-up: `systemctl enable wg-quick@wg0`

See [wg-quick(8)](https://man7.org/linux/man-pages/man8/wg-quick.8.html) for more information.

Run `python3 generate.py -h` for more help about the generator.

```
wg-ops: WireGuard configuration extended generator
OPTIONS
    -h Display this help and quit.
    -k Output generated config to standard output
    -o <filename> Output generated config to file. Default is {source_filename}.gen
TAGS
    #enable-bbr
    #enable-forward
    #iptables-forward
    #route-to table
    #route-from table
    #udp2raw-server name port password
    #udp2raw-client name port remote password
    #udp2raw-client-mux name mux port remote password
    #gost-server name port
    #gost-client name port remote
    #gost-client-mux name mux port remote
    #use-tunnel name
```

## Notice

Make sure to setup firewall. UFW is recommended.

For a forwarding server, the following commands might be needed:

```
ufw route allow in on wg0 out on wg0
```

Reload script only reload wireguard configs. Changes made to tunnels will not work without restart.
