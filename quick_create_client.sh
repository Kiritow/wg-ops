#!/bin/bash

export WG_MYPRIK=$(wg genkey)
export WG_MYPUBK=$(echo $WG_MYPRIK | wg pubkey)

export TMUX_PATH=$(which tmux)

python3 wgop_quick_client.py
python3 wgop_generate.py

chmod +x start.sh
chmod +x stop.sh
chmod +x restart.sh
chmod +x reload.sh
