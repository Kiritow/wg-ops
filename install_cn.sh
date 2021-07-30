#!/bin/bash
set -xe

sudo apt update
sudo apt install -y curl wireguard python3

mkdir -p local

mkdir -p bin
cd bin

git clone https://gitee.com/kiritow/wg-op-binary
cd wg-op-binary

openssl enc -aes-256-cbc -pbkdf2 -a -d -in bin.01 -out ../udp2raw_amd64
openssl enc -aes-256-cbc -pbkdf2 -a -d -in bin.02 -out ../speederv2_amd64

cd ..
rm -rf wg-op-binary

cd ..

VERIFIED_HASH="a7ce38b2c30980be4e71c3af8a9c1db8183db349c699fa6f843e67add7e6cca2"
TEMP_HASH=$(sha256sum bin/udp2raw_amd64 | awk '{print $1}')
if [ "$TEMP_HASH" == "$VERIFIED_HASH" ]
then
    echo "[OK] udp2raw hash match: $TEMP_HASH"
else
    echo "[WARN] udp2raw hash mismatch: $TEMP_HASH. Expected: $VERIFIED_HASH"
fi

VERIFIED_HASH="3cf8f6c1e9baa530170368efb8a4bfcd6e75f88c2726ecbf2a75261dd1dd9fd5"
TEMP_HASH=$(sha256sum bin/speederv2_amd64 | awk '{print $1}')
if [ "$TEMP_HASH" == "$VERIFIED_HASH" ]
then
    echo "[OK] speederv2 hash match: $TEMP_HASH"
else
    echo "[WARN] speederv2 hash mismatch: $TEMP_HASH. Expected: $VERIFIED_HASH"
fi