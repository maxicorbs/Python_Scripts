#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="mac", help="MAC address to change to")
    (values, arguments) = parser.parse_args()
    if not values.interface:
        parser.error("No interface, use --help")
    elif not values.mac:
        parser.error("No MAC, use --help")
    return values

def change_mac(interface, mac):
    subprocess.call(["ifconfig", interface, "down"])
    print("Taking down " + interface + "...")
    subprocess.call(["ifconfig", interface, "hw", "ether", mac])
    subprocess.call(["ifconfig", interface, "up"])
    subprocess.call("ifconfig")

values = get_arguments()
change_mac(values.interface, values.mac)

def check_mac(interface, mac):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_address_search_result:
        print(mac_address_search_result.group(0))
    else:
        print("Unable to read MAC address")
    if mac_address_search_result.group(0) == mac:
        print("Your MAC address was successfully changed")
    else:
        print("Something went wrong")

check_mac(values.interface, values.mac)

# interface = input("What interface?")
# mac = inut("What MAC address?")
# interface = values.interface
# mac = values.mac


# subprocess.call("ifconfig " + interface + " hw ether " + mac, shell=True)
# print("Changing MAC address to " + mac)
# subprocess.call("ifconfig " + interface +" up", shell=True)
# print("Enabling " + interface)
# print("Running ifconfig...")
# subprocess.call("ifconfig", shell=True)
