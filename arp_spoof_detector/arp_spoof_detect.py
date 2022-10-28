#!/usr/env/bin python
import argparse
import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return(answered_list[0][1].hwsrc)

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
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("You are under attack")
            else:
                print("Everything looks fine")
                print(packet.show())
        except IndexError:
            pass

sniff(args.interface)