# WireGuard Ops

[wg-quick](https://man7.org/linux/man-pages/man8/wg-quick.8.html) compatiable config generator with additional features supported.

## Basic Usage

1. Clone this repo with `git clone https://github.com/Kiritow/wg-ops`

2. Run `install.sh`. (May prompt sudo)

3. Write a valid WireGuard `wg-quick` config file, with supported extension tags. (see below)

4. Run `python3 generate.py` to convert extension tags into config lines.

5. Bring it up with `wg-quick up`

Start as service: `systemctl start wg-quick@wg0`

Start service on system start-up: `systemctl enable wg-quick@wg0`

See [wg-quick(8)](https://man7.org/linux/man-pages/man8/wg-quick.8.html) for more information.

## Options

python3 **generate.py** [-h] [-k] [-o *filename*] *source_filename*

**-h** Display this help and quit.

**-k** Output generated config to standard output

**-o** *filename* Output generated config to `filename`. Default write to *source_filename*.gen

## Generic Tags

**enable-bbr**

Enable [TCP BBR](https://en.wikipedia.org/wiki/TCP_congestion_control#TCP_BBR). Most of the time it's useful on VPS.

**enable-forward**

Set `net.ipv4.ip_forward` to 1. Enable ip packet forward.

**iptables-forward**

Add iptables rules to accept forward from this wireguard interface. Example: `iptables -A FORWARD -i wg0 -j ACCEPT`

**iptables-gateway**

Add iptables rules to masquerade source ip as a gateway. Example: `iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE`

**podman-user** *username*

Run podman container as `username`. Default to `root`.

**enable-dns-reload**

Enable DNS reloader for peers with endpoint. For each peer, a transient timer and service will be created and try resolving endpoint domain name every 30 seconds. If the dns record of a domain changes, wg-ops will try to update wireguard interface endpoint settings live.

## Tunnel Tags

**udp2raw-server** *name* *port* *password*

Setup a [udp2raw](https://github.com/wangyu-/udp2raw-tunnel) server. Raw mode set to `fake-tcp`. Expose & listen on port `port`.

**udp2raw-client** *name* *port* *remote* *password*

Setup a udp2raw client. Listen on port `port`.

**udp2raw-client-mux** *name* *mux_size* *port* *remote* *password*

Setup multiple (up to `mux_size`) udp2raw clients. Listen on ports from `port` to `port + mux_size`

**gost-server** *name* *port*

Setup a [gost](https://github.com/ginuerzh/gost) server. Forward mode set to `relay+tls`. Expose & listen on port `port`.

**gost-client** *name* *port* *remote*

Setup a gost client. Listen on port `port`.

**gost-client-mux** *name* *mux_size* *port* *remote*

Setup multiple (up to `mux_size`) gost clients. Listen on ports from `port` to `port + mux_size`

**trojan-server** *name* *port* *password* *cert_path* *key_path*

Setup a [trojan-go](https://github.com/p4gefau1t/trojan-go) server. Expose & listen on port `port`.

Requires a ssl certificate signed by trusted CA.

[acme.sh](https://github.com/acmesh-official/acme.sh) is recommended for acquiring ssl certs. Make sure use `fullchain.cer` as `cert_path`

**trojan-client** *name* *port* *password* *remote_host* *target_port*

Setup a trojan-go client. Listen on port `port`.

**trojan-client-mux** *name* *mux_size* *port* *password* *remote_host* *target_port*

Setup multiple (up to `mux_size`) trojan-go clients. Listen on ports from `port` to `port + mux_size`

## Peer Tags

**use-tunnel** *name*

Use tunnel `name` for this peer. wg-ops may add `Endpoint=` or use `wg set peer` to fullfill this requirement.

## Route Tags

**route-to** *ip_route_table*

Used in chained WireGuard settings. Accept any traffic from `ip_route_table`.

Interface marked with `route-to` should have only **one** peer.

**route-from** *ip_route_table*

Used in chained WireGuard settings. Route traffic from all peers or a marked peer with `ip_route_table`.

Example: The following config means all traffic from `10.44.0.2` will be forward to `10.33.0.1`

wg0.conf (Should have only one peer)

```
[Interface]
Address=10.33.0.2
#route-to TABLE

[Peer]
AllowedIPs=10.33.0.1
```

wg1.conf

```
[Interface]
Address=10.44.0.1

[Peer]
AllowedIPs=10.44.0.2
#route-from TABLE
```

## Notice

Make sure to setup firewall for better security. [ufw](http://manpages.ubuntu.com/manpages/bionic/man8/ufw.8.html) is recommended for Ubuntu.
