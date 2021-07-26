#!/bin/bash

export WG_MYPRIK=$(wg genkey)
export WG_MYPUBK=$(echo $WG_MYPRIK | wg pubkey)

python3 tool_quick_client.py
python3 tool_generate.py

chmod +x start.sh
chmod +x stop.sh
chmod +x restart.sh
