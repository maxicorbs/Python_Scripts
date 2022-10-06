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
        print(packet)

sniff(args.interface)