#!/bin/bash
set -e

export WG_MYPRIK=$(wg genkey)
export WG_MYPUBK=$(echo $WG_MYPRIK | wg pubkey)

python3 tool_create.py
python3 tool_generate.py
