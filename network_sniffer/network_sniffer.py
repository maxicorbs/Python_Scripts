#!/usr/env/bin python
import argparse
import scapy.all as scapy
from scapy.layers import http

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on")
    args = parser.parse_args()
    if not args.interface:
        parser.error("No interface provided, use --help")
    # elif not args.target:
    #      parser.error("No target IP provided, use --help")
    return args

args = get_arguments()

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)

        if packet.haslayer(scapy.Raw):
            load = (packet[scapy.Raw].load)
            keywords = ["username", "user", "uname", "login", "pass", "password"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break

sniff(args.interface)