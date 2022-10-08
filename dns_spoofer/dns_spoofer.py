#!/usr/bin/env python
import subprocess
import netfilterqueue

subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", Shell=True)