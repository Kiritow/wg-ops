#!/bin/bash

echo 'Detecting Public IP address...'
export WG_PUBLICIP=$(curl ident.me)

python3 wgop_display.py
