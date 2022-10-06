#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--IP", dest="ip", help="IP range to scan")
    (values, arguments) = parser.parse_args()
    if not values.ip:
        parser.error("No IP provided, use --help")
    return values

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC\n")
    for element in answered:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

values = get_arguments()

scan(values.ip)