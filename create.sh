#!/bin/bash

export WG_MYPRIK=$(wg genkey)
export WG_MYPUBK=$(echo $WG_MYPRIK | wg pubkey)
export WG_PUBLICIP=$(curl ident.me)

python3 tool_create.py
python3 tool_generate.py

chmod +x start.sh
