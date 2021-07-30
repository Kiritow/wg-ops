#!/bin/bash
set -xe

sudo apt update
sudo apt install -y curl wireguard python3

mkdir -p local
mkdir -p local/tunnel

mkdir -p bin
cd bin

rm -rf wg-op-binary
git clone https://gitee.com/kiritow/wg-op-binary
cd wg-op-binary

openssl enc -aes-256-cbc -pbkdf2 -a -d -in bin.01 -out ../udp2raw_amd64
openssl enc -aes-256-cbc -pbkdf2 -a -d -in bin.02 -out ../speederv2_amd64
chmod +x ../udp2raw_amd64
chmod +x ../speederv2_amd64

cd ..
rm -rf wg-op-binary

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
