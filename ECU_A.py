import isotp
import can
import time
import threading
from Crypto.Util.Padding import pad, unpad
import os
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import random
# ===========================
#      GLOBAL VARIABLES
# ===========================

C_KEY = b"MY_SUPER_KEY_123"

VIN = b"VF1ABCDE123456789"
Model = b"nissan patrol 2025"
config = b"\x00\x00"        #15-counter, 14-CMAC

RID_1234_result = None
RID_5678_result = None

engine_started = False
security_access = False
session = 1           # 1=default , 2=programming , 3=extended
since_access = None
current_seed = None

once_3e80_flag = True

x11_counter = 0   #No. of wrong UDS reset ECU
x22_counter = 0   #No. of wrong UDS read DID attempts
x31_counter = 0   #No. of wrong UDS routine controller attempts
last_time_blocked = time.time()
blocked = False
seed_length = 4

def calculate_expected_key(seed):
    xor_value = 0x11223344     
    xor_bytes = xor_value.to_bytes((xor_value.bit_length() + 7) // 8, "big")

    if len(xor_bytes) < len(seed):
        xor_bytes = xor_bytes.rjust(len(seed), b'\x00')

    expected = bytes(s ^ x for s, x in zip(seed, xor_bytes))
    return expected

def ecu_generate_seed():
    global seed_length
    #seed = os.urandom(seed_length)

    seed_int = random.randint(0x11110000, 0x111108E8)

    seed = seed_int.to_bytes(4, 'big')


    print(f"[ECU] Generated Seed: {seed.hex().upper()}")
    return seed

# ===========================
#      CAN + ISOTP SETUP
# ===========================

self_bus = can.interface.Bus('vcan0',interface='socketcan',
    can_filters=[
        {"can_id": 0x7E0, "can_mask": 0x7FF},
        {"can_id": 0x7E8, "can_mask": 0x7FF}])

self_addr = isotp.Address(isotp.AddressingMode.Normal_11bits,rxid=0x7E0,txid=0x7E8)

self_stack = isotp.CanStack(bus=self_bus, address=self_addr)


# ===========================
#      HELPER FUNCTIONS
# ===========================


def calc_cmac(data: bytes) -> bytes:
    c = CMAC.new(C_KEY, ciphermod=AES)
    c.update(data)
    return c.digest()[:8]


def ecu_validate_key(current_seed, tester_key):
    if current_seed is None:
        return False
    expected = calculate_expected_key(current_seed)
    return tester_key == expected

def RID_1234():
    return os.urandom(2)


def RID_5678():
    return b"\x11\x11"


# ===========================
#      SESSION HANDLING
# ===========================

def diagnostic_session(req):
    global session, security_access, config

    sub = req[1]
    
    value = int.from_bytes(config, "big")


    # -------- SUB = 0x01 → default session --------
    if sub == 0x01:
        session = 1
        return 0x50

    # -------- SUB = 0x02 or 0x03 --------
    elif sub in (0x02, 0x03):

        
        if not security_access:
            return 0x33     # SecurityAccessDenied

        
        if value & (1 << 14):

           
            if len(req) < (2 + 8):
                return 0x13     # incorrect length

            cmd_no_cmac = req[:2]     
            rcv_cmac = req[-8:]       
            exp_cmac = calc_cmac(cmd_no_cmac)

            if rcv_cmac != exp_cmac:
                print("Invalid CMAC for session control!")
                return 0x33     # SecurityAccessDenied

        
        session = sub
        return 0x50

    # -------- Subfunction --------
    else:
        return 0x10     # general reject


# def diagnostic_session(req):
#     global session, security_access

#     if req[1] == 0x01:
#         session = 1
#         return 0x50
#     elif req[1] == 0x02:
#         if security_access :
#             session = 2
#             return 0x50
#         else :
#             return 0x33
#     elif req[1] == 0x03:
#         if security_access :
#             session = 3
#             return 0x50
#         else :
#             return 0x33
#     else : 
#         return 0x10


# ===========================
#      SESSION TIMEOUT
# ===========================

def time_s3():
    global session, current_seed, since_access

    while True:
        if session in (2, 3) and time.time() - since_access > 5:
                print("Returning to Default session...")
                session = 1
                #security_access = False
                current_seed = None
        time.sleep(0.5)


# ============================
#      MAIN ECU RECEIVER
# ============================
def cmd_counter():
    global x22_counter, x31_counter, x11_counter, last_time_blocked, blocked, config
    last_time_blocked = time.time()
    x31_counter = 0
    x22_counter = 0
    x11_counter = 0
    value = int.from_bytes(config, "big")

    while value & (1 << 15):

        if x31_counter == 3 or x22_counter == 3 or x11_counter == 3:
            if not blocked:
                blocked = True
                last_time_blocked = time.time()

        if time.time() - last_time_blocked > 20 and blocked:
            blocked = False
            x31_counter = 0
            x22_counter = 0
            x11_counter = 0
        value = int.from_bytes(config, "big")

def receiving(stack):
    global VIN, Model, config
    global session, security_access, current_seed
    global RID_1234_result, RID_5678_result
    global once_3e80_flag, engine_started, since_access
    global x22_counter, x31_counter, x11_counter, last_time_blocked, blocked

    while True:

        if stack.available():
            req = stack.recv()

            if blocked:
                print(f"block!! ..remaining {20 -(time.time() - last_time_blocked)}seconds")
                continue

            if not req or len(req) < 2 :
                stack.send(bytes([0x7F, req[0], 0x13]))
                continue

            # -----------------------------
            #     3E 80 (Auto tester)
            # -----------------------------
            if req != bytes([0x3E, 0x80]):
                print("[ECU] Received:", req.hex().upper())

            if req == bytes([0x3E, 0x80]) and once_3e80_flag:
                print("[ECU] Received:", req.hex().upper())
                once_3e80_flag = False
            if req[0] == 0x01:
                if req[:2] == bytes([0x01, 0x0C]):  # RPM
                    if not engine_started:
                        resp = bytes([0x7F, 0x01, 0x22]) #condition not correct
                        stack.send(resp)
                    else:
                        rpm = 6904 * 4
                        resp = bytes([0x41, 0x0C, (rpm>>8)&0xFF, rpm&0xFF])

                        stack.send(resp)

                elif req[:2] == bytes([0x01, 0x0D]):  # Speed
                    resp = bytes([0x41, 0x0D, 50])
                    stack.send(resp)
                else :
                    stack.send(bytes([0x7F, 0x01, 0x31]))
                    continue

            elif req[:2] == bytes([0x09, 0x02]):  # VIN
                resp = [0x49, 0x02] + list(VIN)
                stack.send(resp)       


            # ===========================================================
            #               SERVICE 0x10 — DIAGNOSTIC SESSION
            # ===========================================================
            elif req[0] == 0x10:

                # # length check
                # if len(req) != 2:
                #     stack.send(bytes([0x7F, 0x10, 0x13]))
                #     continue

                code = diagnostic_session(req)

                if code == 0x50:
                    since_access = time.time()
                    stack.send(bytes([0x50, req[1]]))

                elif code == 0x33:
                    stack.send(bytes([0x7F, 0x10, 0x33]))

                else:
                    stack.send(bytes([0x7F, 0x10, 0x10]))
                continue

            # ===========================================================
            #           SERVICE 0x3E — TESTER PRESENT (MANUAL)
            # ===========================================================
            elif req[:2] == bytes([0x3E, 0x00]):

                if len(req) != 2:
                    stack.send(bytes([0x7F, 0x3E, 0x13]))
                    continue

                if session in (2, 3):
                    since_access = time.time()
                    stack.send(bytes([0x7E, 0x00]))
                else:
                    stack.send(bytes([0x7F, 0x3E, 0x22]))
                continue

            # ===========================================================
            #          SERVICE 0x3E — AUTO TESTER PRESENT
            # ===========================================================
            elif req[:2] == bytes([0x3E, 0x80]):

                if len(req) != 2:
                    stack.send(bytes([0x7F, 0x3E, 0x13]))
                    continue

                if session in (2, 3):
                    since_access = time.time()
                continue

            # ===========================================================
            #           SERVICE 0x27 — SECURITY ACCESS (SEED)
            # ===========================================================
            elif req[:2] == bytes([0x27, 0x01]):

                if len(req) != 2:
                    stack.send(bytes([0x7F, 0x27, 0x13]))
                    continue

                current_seed = ecu_generate_seed()
                stack.send(bytes([0x67, 0x01]) + current_seed)
                continue

            # ===========================================================
            #           SERVICE 0x27 — SECURITY ACCESS (KEY)
            # ===========================================================
            elif req[:2] == bytes([0x27, 0x02]):

                # if len(req) != 6:
                #     stack.send(bytes([0x7F, 0x27, 0x13]))
                #     continue
                if current_seed is None:
                    stack.send(bytes([0x7F, 0x27, 0x22]))
                    continue
                value = int.from_bytes(config, "big")

                tester_key   = req[2:] 

                if value & (1 << 14):

                    key_len = len(current_seed)
                    if len(req) < 2 + key_len + 8:    # SID + SF + key + CMAC
                        print("CMAC missing!!")
                        stack.send(bytes([0x7F, req[0], 0x33]))
                        continue

                    tester_key   = req[2:-8]          
                    rcv_h  = req[-8:]          
                    exp_h  = calc_cmac(tester_key)   

                    if rcv_h != exp_h:
                        print("Invalid CMAC!!")
                        stack.send(bytes([0x7F, req[0], 0x33]))  # SecurityAccessDenied
                        continue

                if ecu_validate_key(current_seed, tester_key):
                    security_access = True
                    stack.send(bytes([0x67, 0x02]))
                else:
                    stack.send(bytes([0x7F, 0x27, 0x35]))
                continue

            # ===========================================================
            #        SERVICE 0x22 — READ DATA BY IDENTIFIER
            # ===========================================================

            # ---- VIN ----
            elif req[0] == 0x22:
                if len(req) != 3:
                    stack.send(bytes([0x7F, 0x22, 0x13]))
                    continue

                if req[:3] == bytes([0x22, 0xF1, 0x90]):

                    # if len(req) != 3:
                    #     stack.send(bytes([0x7F, 0x22, 0x13]))
                    #     continue

                    if session in (2, 3):
                        stack.send(bytes([0x62, 0xF1, 0x90]) + VIN)
                    else:
                        stack.send(bytes([0x7F, 0x22, 0x22]))
                    continue

                # ---- Model ----
                elif req[:3] == bytes([0x22, 0xF1, 0x8C]):

                    # if len(req) != 3:
                    #     stack.send(bytes([0x7F, 0x22, 0x13]))
                    #     continue

                    if session in (2, 3):
                        stack.send(bytes([0x62, 0xF1, 0x8C]) + Model)
                    else:
                        stack.send(bytes([0x7F, 0x22, 0x22]))
                    continue

                # ---- Config ----
                elif req[:3] == bytes([0x22, 0xF1, 0xA0]):

                    if len(req) != 3:
                        stack.send(bytes([0x7F, 0x22, 0x13]))
                        continue

                    stack.send(bytes([0x62, 0xF1, 0xA0]) + config)
                    continue

                else :
                    stack.send(bytes([0x7F, 0x22, 0x31]))
                    x22_counter += 1
                    continue

            # ===========================================================
            #       SERVICE 0x2E — WRITE DATA BY IDENTIFIER
            # ===========================================================
            elif req[:3] == bytes([0x2E, 0xF1, 0xA0]):

                if len(req) < 5:
                    stack.send(bytes([0x7F, 0x2E, 0x13]))
                    continue

                if security_access:
                    if len(req[3:]) == 2:
                        config = req[3:]
                        value = int.from_bytes(config, "big")
                        if value & (1 << 15) and not t3.is_alive():
                            t3.start()
                        stack.send(bytes([0x6E, 0xF1, 0xA0]))
                    else: 
                        stack.send(bytes([0x7F, 0x2E, 0x13]))
                        continue 

                else:
                    stack.send(bytes([0x7F, 0x2E, 0x33]))
                continue

            # ===========================================================
            #         SERVICE 0x31 — ROUTINE CONTROL
            # ===========================================================
            
            elif req[0] == 0x31:
                valid_SF= bytes([0x01,0x02,0x03])
                if req[1] not in valid_SF:
                    stack.send(bytes([0x7F, 0x31, 0x12]))
                    continue
            # ===========================================================
            #         SERVICE 0x31 — ROUTINE CONTROL (1234)
            # ===========================================================
                elif req[:4] == bytes([0x31, 0x01, 0x12, 0x34]):

                    if len(req) != 4:
                        stack.send(bytes([0x7F, 0x31, 0x13]))
                        continue

                    if security_access:
                        RID_1234_result = RID_1234()
                        stack.send(bytes([0x71, 0x01, 0x12, 0x34]))
                    else:
                        stack.send(bytes([0x7F, 0x31, 0x33]))
                    continue

                elif req[:4] == bytes([0x31, 0x03, 0x12, 0x34]):

                    if len(req) != 4:
                        stack.send(bytes([0x7F, 0x31, 0x13]))
                        continue

                    if security_access and RID_1234_result is not None:
                        stack.send(bytes([0x71, 0x03, 0x12, 0x34]) + RID_1234_result)
                    elif security_access:
                        stack.send(bytes([0x7F, 0x31, 0x22]))
                    else:
                        stack.send(bytes([0x7F, 0x31, 0x33]))
                    continue
            # ===========================================================
            #         SERVICE 0x31 — ROUTINE CONTROL (5678)
            # ===========================================================
                elif req[:4] == bytes([0x31, 0x01, 0x56, 0x78]):

                    if len(req) != 4:
                        stack.send(bytes([0x7F, 0x31, 0x13]))
                        continue

                    if session in (2, 3):
                        RID_5678_result = RID_5678()
                        stack.send(bytes([0x71, 0x01, 0x56, 0x78]))
                    else:
                        stack.send(bytes([0x7F, 0x31, 0x22]))
                    continue

                elif req[:4] == bytes([0x31, 0x03, 0x56, 0x78]):

                    if len(req) != 4:
                        stack.send(bytes([0x7F, 0x31, 0x13]))
                        continue

                    if session in (2, 3) and RID_5678_result is not None:
                        stack.send(bytes([0x71, 0x03, 0x56, 0x78]) + RID_5678_result)
                    else:
                        stack.send(bytes([0x7F, 0x31, 0x22]))
                    continue
                elif req[:2] == bytes([0x31, 0x03]) or req[:2] == bytes([0x31, 0x01]):
                    stack.send(bytes([0x7F, 0x31, 0x31]))
                    x31_counter += 1
                    
                else :
                    stack.send(bytes([0x7F, 0x31, 0x12]))
            # ===========================================================
            #         SERVICE 0x11 — ECU RESET
            # ===========================================================
            elif req[:2] == bytes([0x11, 0x03]) or req[:2] == bytes([0x11, 0x02]) or req[:2] == bytes([0x11, 0x01]):

                if len(req) != 2:
                    stack.send(bytes([0x7F, 0x11, 0x13]))
                    continue

                stack.send(bytes([0x51, 0x01]))

                x11_counter += 1
                
                # Reset internal states
                RID_1234_result = None
                RID_5678_result = None
                security_access = False
                session = 1
                since_access = None
                current_seed = None
                once_3e80_flag = True

                if engine_started:
                    print("Engine stopped.")
                    engine_started = False
                    print("Press Enter to start engine:")

                
                continue

            # ===========================================================
            #       SERVICE NOT SUPPORTED
            # ===========================================================
            else:
                stack.send(bytes([0x7F, req[0], 0x11]))
                continue

        stack.process()
        time.sleep(0.01)


# ===========================
#              MAIN LOOP
# ===========================

if __name__ == "__main__":

    t1 = threading.Thread(target=receiving, args=(self_stack,))
    t2 = threading.Thread(target=time_s3)
    t3 = threading.Thread(target=cmd_counter)
    t1.start()
    t2.start()
    

    print("Press Enter to start the engine:")

    while True:
        user_input = input()
        if user_input == "":
            print("Engine started!")
            engine_started = True
        else:
            print("Press Enter only.")
