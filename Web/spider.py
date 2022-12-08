#!/usr/bin/env Python

import requests
import re
import urllib.parse

target_url = "https://google.com"

def extract_links(url):
    response = requests.get(url)
    return re.findall('(?:href=")(.*?)"', str(response.content))

href_links = extract_links(target_url)
for line in href_links:
    line = urllib.parse.urljoin(target_url, line)
    if target_url in line:
        print(line)