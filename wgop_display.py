# -*- coding: utf-8 -*-
import os
from wgop_common import load_config, get_quick_config


config = load_config()
if not config:
    print("[WARN] Config not found.")
    exit(1)


quicks = get_quick_config(config, os.getenv("WG_PUBLICIP"))
if not quicks:
    print("No server configured.")
    exit(0)

print("===== Quick Import =====")
for quick_info in quicks:
    print("Connect to this server via tunnel at port {}: (credential included)\n{}\n".format(quick_info["port"], quick_info["qcs"]))
