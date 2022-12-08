#!/usr/bin/env Python

import requests

def request(url):
    try:
        return requests.get("http://" + url)
    except requests.exceptions.ConnectionError:
        pass
target_url = "google.com"
with open("/home/kali/common.txt", "r") as wordlist:
    for line in wordlist:
        word = line.strip()
        test_url = target_url + "/" + word
        response = request(test_url)
        if response:
            print("[+] Discovered URL at: " + test_url)





