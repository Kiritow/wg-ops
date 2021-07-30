# Wireguard Ops

A group of Interactive bash scripts for [Wireguard](https://github.com/WireGuard/wireguard-go) over [udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel), with optional [UDPSpeeder](https://github.com/wangyu-/UDPspeeder) support.

## Usage

1. Run `install.sh`. (May require Super user permission)

2. Run `create.sh` and fill in content interactively.

3. Run the generated `start.sh`. (May require Super user permission)

Start as service: `systemctl start wg-quick@wg0`

Start service on system start-up: `systemctl enable wg-quick@wg0`

See [wg-quick(8)](https://man7.org/linux/man-pages/man8/wg-quick.8.html) for more information.

## Notice

Make sure to setup firewall. UFW is recommended.

For a forwarding server, the following commands might be needed:

```
ufw route allow in on wg0 out on wg0
```
