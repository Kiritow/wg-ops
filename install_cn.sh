#!/bin/bash
set -xe

sudo apt update
sudo apt install -y curl wireguard python3

. /etc/os-release
echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/Release.key" | sudo apt-key add -
sudo apt update
sudo apt install -y podman

mkdir -p local
mkdir -p local/tunnel

mkdir -p bin
cd bin

rm -rf wg-op-binary
git clone https://gitee.com/kiritow/wg-op-binary
cd wg-op-binary

openssl enc -aes-256-cbc -pbkdf2 -a -d -in bin.01 -out ../udp2raw_amd64
openssl enc -aes-256-cbc -pbkdf2 -a -d -in bin.02 -out ../speederv2_amd64
openssl enc -aes-256-cbc -pbkdf2 -a -d -in bin.03 -out ../gost
chmod +x ../udp2raw_amd64
chmod +x ../speederv2_amd64
chmod +x ../gost

cd ..
rm -rf wg-op-binary

cd ..

VERIFIED_TUNNEL_HASH="a7ce38b2c30980be4e71c3af8a9c1db8183db349c699fa6f843e67add7e6cca2"
LOCAL_TUNNEL_HASH=$(sha256sum bin/udp2raw_amd64 | awk '{print $1}')

VERIFIED_SPEEDER_HASH="3cf8f6c1e9baa530170368efb8a4bfcd6e75f88c2726ecbf2a75261dd1dd9fd5"
LOCAL_SPEEDER_HASH=$(sha256sum bin/speederv2_amd64 | awk '{print $1}')

VERIFIED_GOST_HASH="5434f730594d29b933087dcaf1ae680bee7077abd021c004f28287deccfe49b5"
LOCAL_GOST_HASH=$(sha256sum bin/gost | awk '{print $1}')

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

if [ "$LOCAL_GOST_HASH" == "$VERIFIED_GOST_HASH" ]
then
    echo "[OK] gost hash match: $LOCAL_GOST_HASH"
else
    echo "[WARN] gost hash mismatch: $LOCAL_GOST_HASH. Expected: $VERIFIED_GOST_HASH"
fi

sudo podman build . -f DockerfileCN -t ubuntu-cn:latest
sudo podman tag ubuntu-cn:latest ubuntu:latest
sudo podman build . -f DockerfileBuildEnv -t wg-ops-buildenv
sudo podman build . -f DockerfileRunEnv -t wg-ops-runenv

podman build . -f DockerfileCN -t ubuntu-cn:latest
podman tag ubuntu-cn:latest ubuntu:latest
podman build . -f DockerfileBuildEnv -t wg-ops-buildenv
podman build . -f DockerfileRunEnv -t wg-ops-runenv

CONTAINER_ID=$(podman run --rm -it -v ./bin:/root/bin -d wg-ops-buildenv)
podman cp mux.c $CONTAINER_ID:/root/
podman exec -it $CONTAINER_ID bash -c "cd /root && gcc -O3 -o bin/mux mux.c"
podman stop $CONTAINER_ID
