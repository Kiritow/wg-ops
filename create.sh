#!/bin/bash

echo 'Detecting Public IP address...'
export WG_PUBLICIP=$(curl ident.me)

export WG_MYPRIK=$(wg genkey)
export WG_MYPUBK=$(echo $WG_MYPRIK | wg pubkey)

python3 tool_create.py
python3 tool_generate.py

chmod +x start.sh
chmod +x stop.sh
chmod +x restart.sh
