#!/usr/bin/env python
import socket

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("10.10.10.10", 4444))
listener.listen(0) #backlog value, doesn't have to be anything for no
print("[+] Waiting for connections")
listener.accept() #tells our computer to accept incoming
print("[+] Got a connection")