#!/usr/bin/env python
import subprocess
import netfilterqueue
import scapy.all as scapy
from scapy.utils import hexdump

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet.show())
    hexdump(packet)
    packet.accept()


try:
    print("[+] Amening IP tables")
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 1", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 1", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("\r\n[-] Detected CTRL + C.....Quitting and restoring IP tables")
    subprocess.call("iptables --flush", shell=True)

