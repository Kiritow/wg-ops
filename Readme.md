# Wireguard Ops

Interactive setup scripts for [Wireguard](https://github.com/WireGuard/wireguard-go) over [udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel).

## Usage

1. Run `install.sh`. (May require Super user permission)

2. Run `create.sh` and fill in content interactively.

3. Run the generated `start.sh`. (May require Super user permission)

## Notice

Make sure to setup firewall. UFW is recommended.

For a forwarding server, the following commands might be needed:

```
ufw route allow in on wg0 out on wg0
```
