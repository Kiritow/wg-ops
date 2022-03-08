#!/bin/bash
set -xe

sudo apt update
sudo apt install -y curl wireguard python3 unzip

. /etc/os-release
echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/Release.key" | sudo apt-key add -
sudo apt update
sudo apt install -y podman

mkdir -p local
mkdir -p local/tunnel

mkdir -p bin
cd bin

curl -vL https://github.com/wangyu-/udp2raw-tunnel/releases/download/20200818.0/udp2raw_binaries.tar.gz -o udp2raw.tgz
tar -xvzf udp2raw.tgz udp2raw_amd64
chmod +x udp2raw_amd64
rm udp2raw.tgz

curl -vL https://github.com/wangyu-/UDPspeeder/releases/download/20210116.0/speederv2_binaries.tar.gz -o udpspeeder.tgz
tar -xvzf udpspeeder.tgz speederv2_amd64
chmod +x speederv2_amd64
rm udpspeeder.tgz

curl -vL https://github.com/ginuerzh/gost/releases/download/v2.11.1/gost-linux-amd64-2.11.1.gz -o gost.gz
gzip -cd gost.gz > gost
chmod +x gost
rm gost.gz

curl -vL https://github.com/p4gefau1t/trojan-go/releases/download/v0.10.6/trojan-go-linux-amd64.zip -o trojan.zip
unzip -p trojan.zip trojan-go > trojan-go
chmod +x trojan-go
rm trojan.zip

cd ..

VERIFIED_TUNNEL_HASH="a7ce38b2c30980be4e71c3af8a9c1db8183db349c699fa6f843e67add7e6cca2"
LOCAL_TUNNEL_HASH=$(sha256sum bin/udp2raw_amd64 | awk '{print $1}')

VERIFIED_SPEEDER_HASH="3cf8f6c1e9baa530170368efb8a4bfcd6e75f88c2726ecbf2a75261dd1dd9fd5"
LOCAL_SPEEDER_HASH=$(sha256sum bin/speederv2_amd64 | awk '{print $1}')

VERIFIED_GOST_HASH="5434f730594d29b933087dcaf1ae680bee7077abd021c004f28287deccfe49b5"
LOCAL_GOST_HASH=$(sha256sum bin/gost | awk '{print $1}')

VERIFIED_TROJANGO_HASH="cb7db31244ec4213c81cb4ef1080c92b44477a0b1dc101246304846e9d74b640"
LOCAL_TROJANGO_HASH=$(sha256sum bin/trojan-go | awk '{print $1}')

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

if [ "$LOCAL_TROJANGO_HASH" == "$VERIFIED_TROJANGO_HASH" ]
then
    echo "[OK] trojan-go hash match: $LOCAL_TROJANGO_HASH"
else
    echo "[WARN] trojan-go hash mismatch: $LOCAL_TROJANGO_HASH. Expected: $VERIFIED_TROJANGO_HASH"
fi

podman build . -f DockerfileBase -t wg-ops-base:latest
podman build . -f DockerfileBuildEnv -t wg-ops-buildenv:latest
podman build . -f DockerfileRunEnv -t wg-ops-runenv:latest

podman save wg-ops-runenv:latest | sudo podman load

CONTAINER_ID=$(podman run --rm -it -v ./bin:/root/bin -d wg-ops-buildenv)
podman cp mux.c $CONTAINER_ID:/root/
podman exec -it $CONTAINER_ID bash -c "cd /root && gcc -O3 -o bin/mux mux.c"
podman stop $CONTAINER_ID
