#!/bin/bash
set -xe

sudo apt update
sudo apt install -y curl wireguard python3 tmux build-essential

mkdir -p local
mkdir -p local/tunnel

mkdir -p bin
cd bin

gcc -O3 -o w2u ../w2u.c

curl -vL https://github.com/wangyu-/udp2raw-tunnel/releases/download/20200818.0/udp2raw_binaries.tar.gz -o udp2raw.tgz
tar -xvzf udp2raw.tgz udp2raw_amd64
chmod +x udp2raw_amd64
rm udp2raw.tgz

curl -vL https://github.com/wangyu-/UDPspeeder/releases/download/20210116.0/speederv2_binaries.tar.gz -o udpspeeder.tgz
tar -xvzf udpspeeder.tgz speederv2_amd64
chmod +x speederv2_amd64
rm udpspeeder.tgz

cd ..

VERIFIED_TUNNEL_HASH="a7ce38b2c30980be4e71c3af8a9c1db8183db349c699fa6f843e67add7e6cca2"
LOCAL_TUNNEL_HASH=$(sha256sum bin/udp2raw_amd64 | awk '{print $1}')

VERIFIED_SPEEDER_HASH="3cf8f6c1e9baa530170368efb8a4bfcd6e75f88c2726ecbf2a75261dd1dd9fd5"
LOCAL_SPEEDER_HASH=$(sha256sum bin/speederv2_amd64 | awk '{print $1}')

if [ "$LOCAL_TUNNEL_HASH" == "$VERIFIED_TUNNEL_HASH" ]
then
    echo "[OK] udp2raw hash match: $LOCAL_TUNNEL_HASH"
else
    echo "[WARN] udp2raw hash mismatch: $LOCAL_TUNNEL_HASH. Expected: $VERIFIED_TUNNEL_HASH"
fi

if [ "$LOCAL_SPEEDER_HASH" == "$VERIFIED_SPEEDER_HASH" ]
then
    echo "[OK] speederv2 hash match: $LOCAL_SPEEDER_HASH"
else
    echo "[WARN] speederv2 hash mismatch: $LOCAL_SPEEDER_HASH. Expected: $VERIFIED_SPEEDER_HASH"
fi
