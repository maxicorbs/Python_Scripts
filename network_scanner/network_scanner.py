#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="IP range to scan")
    values = parser.parse_args()
    if not values.ip:
        parser.error("No IP provided, use --help")
    return values

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]


    clients_list = []
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        # print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return(clients_list)

def print_result(results_list):
    print("IP\t\t\tMAC\n")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

values = get_arguments()

scan_result = scan(values.ip)
print_result(scan_result)