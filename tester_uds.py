
import time
import can
import isotp
import threading
from Crypto.Hash import CMAC
from Crypto.Cipher import AES


auto_status = False
C_KEY = b"MY_SUPER_KEY_123"
CMAC_ON = False
config = b"\x00\x00"  

A_bus = can.interface.Bus('vcan0', interface='socketcan',
can_filters=[
    {"can_id": 0x7E0, "can_mask": 0x7FF},
    {"can_id": 0x7E8, "can_mask": 0x7FF}
]
)
addrA = isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7E8, txid=0x7E0) #ECU_A = 0x7E0
ECU_A_stack = isotp.CanStack(bus=A_bus, address=addrA)


NRC = {
    0x10: "General reject",
    0x11: "Service Not Supported",
    0x12: "Subfunction Not Supported",
    0x13: "incorrect length",
    0x22: "Conditions Not Correct",
    0x31: "Request Out Of Range",
    0x33: "Security Access Denied",
    0x35: "invalid key",
}

def parse_hex(cmd):
    cmd = cmd.strip().replace(" ", "")      # remove spaces
    
    return bytes.fromhex(cmd) 

def clear_isotp_buffer():
    """Clear ISO-TP receive buffer"""
    ECU_A_stack.process()
    while ECU_A_stack.available():
        ECU_A_stack.recv()

def calc_cmac(data: bytes) -> bytes:
    c = CMAC.new(C_KEY, ciphermod=AES)
    c.update(data)
    return c.digest()[:8]

def tester_calculate_key(seed):

    xor_value = 0x11223344
    xor_bytes = xor_value.to_bytes((xor_value.bit_length() + 7) // 8, "big")

    if len(xor_bytes) < len(seed):
        xor_bytes = xor_bytes.rjust(len(seed), b'\x00')

    key = bytes(s ^ x for s, x in zip(seed, xor_bytes))
    print(f"[Tester] Calculated Key: {key.hex().upper()}")
    return key

        


def interpretation (resp):
    global CMAC_ON, config
    if resp[0] == 0x49 or resp[0] == 0x41:
        if resp[:2] == b'\x49\x02':
            print (f"[positive response]: VIN = {resp[2:].decode('ascii')}")
        elif resp[:2] == b'\x41\x0d':
            print (f"[positive response]: SPEED = {resp[2]} km/h")
        elif resp[:2] == b'\x41\x0c':
            rpm = ( (resp[2] << 8) + resp[3] )>> 2
            print (f"[positive response]: RPM = {rpm} rpm")

    if resp[0] == 0x7F:    ###NRCs
        
        if resp[2] == 0x10:
            print (NRC[0x10])
        elif resp[2] == 0x11:
            print (NRC[0x11])
        elif resp[2] == 0x12:
            print (NRC[0x12])
        elif resp[2] == 0x13:
            print (NRC[0x13])
        elif resp[2] == 0x22:
            print (NRC[0x22])
        elif resp[2] == 0x31:
            print (NRC[0x31])
        elif resp[2] == 0x33:
            print (NRC[0x33])
        elif resp[2] == 0x35:
            print (NRC[0x35])
        

    if resp[:2] == b'\x67\x01':
        key = tester_calculate_key(resp[2:])
        if CMAC_ON :
            h = calc_cmac(key)        

            cmd = b'\x27\x02' + key + h
            clear_isotp_buffer()
            
            send (cmd, ECU_A_stack)
        else :
            cmd = b'\x27\x02' + key 
            clear_isotp_buffer()
            
            send (cmd, ECU_A_stack)

    if resp[:3] == b'\x6E\xF1\xA0':

        value = int.from_bytes(config, "big")
        if value & (1 << 14):
            CMAC_ON = True
            print ("[ECU A] :CMAC ON !!")
        else :
            CMAC_ON = False
           
    elif resp[:3] == b'\x62\xf1\x90':
        print (f"[positive response]: VIN : {resp[3:].decode('ascii')}")
    elif resp[:3] == b'\x62\xf1\x8c':
        print (f"[positive response]: Model : {resp[3:].decode('ascii')}")
    elif resp[:3] == b'\x62\xf1\xa0':
        print (f"[positive response]: config = {resp[3:]}")
    elif resp[:4] == b'\x71\x03\x12\x34':
        print (f"[positive response]: RID_1234_result : {resp[4:].decode('ascii')}")
    elif resp[:4] == b'\x71\x03\x56\x78':
        print (f"[positive response]: RID_5678_result : {resp[4:].decode('ascii')}")
        
def send(cmd, stack):
    clear_isotp_buffer()

    print("[Tester] Sending:", cmd.hex())
    stack.send(cmd)
    timeout = time.time() + 2
    while time.time() < timeout:
        stack.process()
        if stack.available():
            resp = stack.recv()
            print("[ECU_A] Response:", resp.hex())
            interpretation(resp)
            return
        time.sleep(0.01)

    print("time out ..")

def auto_tester_present():
    global auto_status

    while True:
        if auto_status:
            cmd = "3E80"
            cmd = parse_hex(cmd)
            ECU_A_stack.send(cmd)
            ECU_A_stack.process()
            time.sleep(4)
        


if __name__ == "__main__":
    t1 = threading.Thread(target=auto_tester_present)

    t1.start()

    print("UDS is running…")
    print("Enter command like: 1003 / 2701 /..")

    while True:

        cmd = input("command > ").strip()
        if cmd.lower() == "e":
            break
        elif cmd.lower() == "3e":
            if auto_status:
                auto_status = False
                
            else :
                auto_status = True
        else :
            try :

                data = parse_hex(cmd)
                
                if data == bytes([0x10, 0x03]) or data == bytes([0x10, 0x02]):
                    if CMAC_ON:
                        mac = calc_cmac(data)
                        final_cmd = data + mac
                        
                        clear_isotp_buffer()
                        send(final_cmd, ECU_A_stack)
                    else :
                        
                        clear_isotp_buffer()
                        send(data, ECU_A_stack)
                elif data[:3] == bytes([0x2E, 0xF1, 0xA0]):
                    config = data[3:]
                    
                    clear_isotp_buffer()
                    send(data, ECU_A_stack)
                else:
                    
                    clear_isotp_buffer()
                    send(data, ECU_A_stack)
                
            except: 
                print("Enter command like: 1003 / 2701 /..")







# def OBD(event):
#     print("OBD is running…")
#     print("Enter command like: 0902 / 010C /..")

#     while event:

#         cmd = input("command > ").strip()
#         if cmd.lower() == "e":
#             break
#         send(cmd, ECU_A_stack)            

# def UDS():
#     print("UDS is running…")
#     print("Enter command like: 1003 / 2701 /..")

#     while True:

#         cmd = input("command > ").strip()
#         if cmd.lower() == "e":
#             break
#         elif cmd.lower() == "3e":
#             if auto_status:
#                 auto_status = False
#                 auto_tester_present()
#             else :
#                 auto_status = True
#                 auto_tester_present()
#         else:
#             send(cmd, ECU_A_stack)