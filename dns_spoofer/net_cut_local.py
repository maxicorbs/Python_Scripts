#!/usr/bin/env python
import subprocess
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.getpayload())
    print(scapy.packet.show())
    packet.accept()


try:
    print("[+] Amening IP tables")
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("\r\n[-] Detected CTRL + C.....Quitting and restoring IP tables")
    subprocess.call("iptables --flush", shell=True)

