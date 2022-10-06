#!/usr/bin/env python

import optparse

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

values = get_arguments()
print(values.interface, values.mac)