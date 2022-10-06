#!/usr/env/bin python
import argparse

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
print(args.interface)
