#!/bin/bash
set -xe

sudo apt update
sudo apt install -y curl wireguard wireguard-tools python3 unzip

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

curl -vL https://github.com/p4gefau1t/trojan-go/releases/download/v0.10.6/trojan-go-linux-amd64.zip -o trojan.zip
unzip -p trojan.zip trojan-go > trojan-go
chmod +x trojan-go
rm trojan.zip

if [ ! -z "$INSTALL_GOST" ]
then
    curl -vL https://github.com/ginuerzh/gost/releases/download/v2.11.1/gost-linux-amd64-2.11.1.gz -o gost.gz
    gzip -cd gost.gz > gost
    chmod +x gost
    rm gost.gz
else
    echo "skip gost download due to INSTALL_GOST not set"
fi

if [ ! -z "$INSTALL_FRP" ]
then
    curl -vL https://github.com/fatedier/frp/releases/download/v0.44.0/frp_0.44.0_linux_amd64.tar.gz -o frp.tgz
    tar --strip-components=1 -xzvf frp.tgz $(tar -tzvf frp.tgz | grep -e frps$ | awk '{print $6}')
    tar --strip-components=1 -xzvf frp.tgz $(tar -tzvf frp.tgz | grep -e frpc$ | awk '{print $6}')
    rm frp.tgz
else
    echo "skip frp download due to INSTALL_FRP not set"
fi 

cd ..

verify_hash() {
    local hash=$(sha256sum bin/$1 | awk '{print $1}')
    if [ $2 == "$hash" ]
    then
        echo "[OK] $1 hash match: $2"
    else
        echo "[WARN] $1 hash mismatch. Expected $2, got $hash"
        sleep 1
    fi
}

verify_hash "udp2raw_amd64" "a7ce38b2c30980be4e71c3af8a9c1db8183db349c699fa6f843e67add7e6cca2"
verify_hash "speederv2_amd64" "3cf8f6c1e9baa530170368efb8a4bfcd6e75f88c2726ecbf2a75261dd1dd9fd5"
verify_hash "trojan-go" "cb7db31244ec4213c81cb4ef1080c92b44477a0b1dc101246304846e9d74b640"

if [ ! -z "$INSTALL_GOST" ]
then
    verify_hash "gost" "5434f730594d29b933087dcaf1ae680bee7077abd021c004f28287deccfe49b5"
fi

if [ ! -z "$INSTALL_FRP"]
then
    verify_hash "frps" "c3f44da41347b9a2d87d8ea02a3d09cdf3ae7b2fe2e31e7b8d7579e3c890de55"
    verify_hash "frpc" "1ce3e3deabb8513414f7998ec908b3ff0ee2bcba25ab3a7d49aeb9be24ba1b8f"
fi

if [ ! -z "$INSTALL_BIRD" ]
then
    sudo apt install -y bird2
else
    echo "skip bird2 installation due to INSTALL_BIRD not set"
fi

if [ ! -z "$INSTALL_PODMAN" ]
then
    . /etc/os-release
    echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
    curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/Release.key" | sudo apt-key add -
    sudo apt update
    sudo apt install -y podman

    podman build . -f DockerfileBase -t wg-ops-base:latest
    podman build . -f DockerfileBuildEnv -t wg-ops-buildenv:latest
    podman build . -f DockerfileRunEnv -t wg-ops-runenv:latest

    podman save wg-ops-runenv:latest | sudo podman load

    CONTAINER_ID=$(podman run --rm -it -v ./bin:/root/bin -d wg-ops-buildenv)
    echo "building with container $CONTAINER_ID"
    podman cp mux.c $CONTAINER_ID:/root/
    podman exec -it $CONTAINER_ID bash -c "cd /root && gcc -O3 -o bin/mux mux.c"
    podman stop $CONTAINER_ID
else
    echo "skip podman installation due to INSTALL_PODMAN not set"
fi
