
import struct
import os
import tkinter as tk
from tkinter import filedialog
import sys
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import time

# Threefish-1024 Constants
BLOCK_SIZE = 128  # 128 bytes = 1024 bits
ROUNDS = 72
WORDS = 16
C240 = 0x1BD11BDAA9FC1A22
# Threefish-1024 Rotation Constants (Skein 1.3 Table 14)
ROTATION_CONSTANTS = [
    # Round 0
    [55, 43, 37, 40, 16, 22, 38, 12],
    # Round 1
    [25, 25, 46, 13, 14, 13, 52, 57],
    # Round 2
    [33, 8, 18, 57, 21, 12, 32, 54],
    # Round 3
    [34, 43, 25, 60, 44,  9, 59, 34],
    # Round 4
    [28,  7, 47, 48, 51,  9, 35, 41],
    # Round 5
    [17,  6, 18, 25, 43, 42, 40, 15],
    # Round 6
    [58,  7, 32, 45, 19, 18,  2, 56],
    # Round 7
    [47, 49, 27, 58, 37, 48, 53, 56],
    # Round 8
    [57, 48, 50, 34, 11,  3, 58, 43],
    # Round 9
    [34, 24, 34, 43, 55,  1, 22, 19],
    # Round 10
    [16, 31, 44, 45,  3, 62, 51, 46],
    # Round 11
    [57, 38, 26,  1, 15, 27, 25, 32],
    # Round 12
    [22, 41, 53, 36, 31, 60, 20, 27],
    # Round 13
    [21, 10, 10, 46, 38,  2, 59, 50],
    # Round 14
    [39, 27, 28, 14, 55, 54, 27, 34],
    # Round 15
    [56, 44, 24, 56, 30, 52, 41, 37],
    # Round 16
    [32, 19, 34, 51, 53, 35, 40, 25],
    # Round 17
    [17, 43, 39, 31, 14, 19, 25, 46],
    # Round 18
    [58, 47, 51, 55,  8, 56, 43, 47],
    # Round 19
    [57, 22, 47, 44, 37, 45,  8, 54],
    # Round 20
    [52, 34, 49, 56, 35, 55, 46, 42],
    # Round 21
    [55, 32, 14, 13, 57, 21, 12, 32],
    # Round 22
    [19, 28, 34, 51, 53, 35, 40, 25],
    # Round 23
    [47, 49, 27, 58, 37, 48, 53, 56],
    # Round 24
    [38,  2, 59, 50, 21, 10, 10, 46],
    # Round 25
    [16, 31, 44, 45,  3, 62, 51, 46],
    # Round 26
    [25, 25, 46, 13, 14, 13, 52, 57],
    # Round 27
    [58,  7, 32, 45, 19, 18,  2, 56],
    # Round 28
    [34, 24, 34, 43, 55,  1, 22, 19],
    # Round 29
    [33,  8, 18, 57, 21, 12, 32, 54],
    # Round 30
    [56, 44, 24, 56, 30, 52, 41, 37],
    # Round 31
    [28,  7, 47, 48, 51,  9, 35, 41],
    # Round 32
    [17,  6, 18, 25, 43, 42, 40, 15],
    # Round 33
    [57, 48, 50, 34, 11,  3, 58, 43],
    # Round 34
    [22, 41, 53, 36, 31, 60, 20, 27],
    # Round 35
    [39, 27, 28, 14, 55, 54, 27, 34],
    # Round 36
    [52, 34, 49, 56, 35, 55, 46, 42],
    # Round 37
    [55, 32, 14, 13, 57, 21, 12, 32],
    # Round 38
    [19, 28, 34, 51, 53, 35, 40, 25],
    # Round 39
    [47, 49, 27, 58, 37, 48, 53, 56],
    # Round 40
    [38,  2, 59, 50, 21, 10, 10, 46],
    # Round 41
    [16, 31, 44, 45,  3, 62, 51, 46],
    # Round 42
    [25, 25, 46, 13, 14, 13, 52, 57],
    # Round 43
    [58,  7, 32, 45, 19, 18,  2, 56],
    # Round 44
    [34, 24, 34, 43, 55,  1, 22, 19],
    # Round 45
    [33,  8, 18, 57, 21, 12, 32, 54],
    # Round 46
    [56, 44, 24, 56, 30, 52, 41, 37],
    # Round 47
    [28,  7, 47, 48, 51,  9, 35, 41],
    # Round 48
    [17,  6, 18, 25, 43, 42, 40, 15],
    # Round 49
    [57, 48, 50, 34, 11,  3, 58, 43],
    # Round 50
    [22, 41, 53, 36, 31, 60, 20, 27],
    # Round 51
    [39, 27, 28, 14, 55, 54, 27, 34],
    # Round 52
    [52, 34, 49, 56, 35, 55, 46, 42],
    # Round 53
    [55, 32, 14, 13, 57, 21, 12, 32],
    # Round 54
    [19, 28, 34, 51, 53, 35, 40, 25],
    # Round 55
    [47, 49, 27, 58, 37, 48, 53, 56],
    # Round 56
    [38,  2, 59, 50, 21, 10, 10, 46],
    # Round 57
    [16, 31, 44, 45,  3, 62, 51, 46],
    # Round 58
    [25, 25, 46, 13, 14, 13, 52, 57],
    # Round 59
    [58,  7, 32, 45, 19, 18,  2, 56],
    # Round 60
    [34, 24, 34, 43, 55,  1, 22, 19],
    # Round 61
    [33,  8, 18, 57, 21, 12, 32, 54],
    # Round 62
    [56, 44, 24, 56, 30, 52, 41, 37],
    # Round 63
    [28,  7, 47, 48, 51,  9, 35, 41],
    # Round 64
    [17,  6, 18, 25, 43, 42, 40, 15],
    # Round 65
    [57, 48, 50, 34, 11,  3, 58, 43],
    # Round 66
    [22, 41, 53, 36, 31, 60, 20, 27],
    # Round 67
    [39, 27, 28, 14, 55, 54, 27, 34],
    # Round 68
    [52, 34, 49, 56, 35, 55, 46, 42],
    # Round 69
    [55, 32, 14, 13, 57, 21, 12, 32],
    # Round 70
    [19, 28, 34, 51, 53, 35, 40, 25],
    # Round 71
    [47, 49, 27, 58, 37, 48, 53, 56]
]
# ECDH Configuration
ECDH_PRIVATE_KEY_FILE = "ecdh_private.pem"
ECDH_PUBLIC_KEY_FILE = "ecdh_public.pem"
SHARED_SECRET_FILE = "shared_secret.bin"

def format_time(seconds):
    """Format seconds into HH:MM:SS"""
    return time.strftime("%H:%M:%S", time.gmtime(seconds))

def format_time(seconds):
    return time.strftime("%H:%M:%S", time.gmtime(seconds))

def show_progress(current, total, start_time, operation):
    """Display a progress bar with elapsed and remaining time"""
    elapsed_time = time.time() - start_time
    percent = (current / total) * 100
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    
    if current > 0:
        remaining_time = (elapsed_time / current) * (total - current)
    else:
        remaining_time = 0
    
    print(f"\r{operation}: |{bar}| {percent:.1f}% [Elapsed: {format_time(elapsed_time)}, Remaining: {format_time(remaining_time)}]", end="")
    sys.stdout.flush()


# ======================= THREEFISH FIXES ========================
def generate_subkeys(key, tweak):
    """Generate Threefish-1024 subkeys from key and tweak (Skein 3.2.2)"""
    key_words = list(struct.unpack("<16Q", key))
    tweak_words = list(struct.unpack("<2Q", tweak))
    
    # Extend key with C240 constant
    k = key_words.copy()
    k.append(C240)
    for i in range(17):
        k[16] ^= key_words[i] if i < 16 else 0
    k[16] ^= tweak_words[0] ^ tweak_words[1]
    
    # Extend tweak
    t = tweak_words.copy()
    t.append(t[0] ^ t[1])
    
    subkeys = []
    for s in range(ROUNDS // 4 + 1):
        subkey = []
        for i in range(WORDS):
            term = k[(s + i) % 17]
            if i == 8:   term += t[s % 3]
            elif i == 9: term += t[(s + 1) % 3]
            elif i ==10: term += t[(s + 2) % 3]
            elif i ==11: term += t[s % 3]
            elif i ==12: term += t[(s + 1) % 3]
            elif i ==13: term += t[(s + 2) % 3]
            elif i >=14: term += s
            subkey.append(term & 0xFFFFFFFFFFFFFFFF)
        subkeys.append(subkey)
    return subkeys

def mix(x0, x1, r):
    x0 = (x0 + x1) & 0xFFFFFFFFFFFFFFFF
    x1 = ((x1 << r) | (x1 >> (64 - r))) & 0xFFFFFFFFFFFFFFFF
    x1 ^= x0
    return x0, x1

def inv_mix(x0, x1, r):
    x1 ^= x0
    x1 = ((x1 >> r) | (x1 << (64 - r))) & 0xFFFFFFFFFFFFFFFF
    x0 = (x0 - x1) & 0xFFFFFFFFFFFFFFFF
    return x0, x1

def threefish_encrypt_block(plaintext, key, tweak):
    subkeys = generate_subkeys(key, tweak)
    words = list(struct.unpack("<16Q", plaintext))
    s = 0
    for round in range(ROUNDS):
        if round % 4 == 0:
            for i in range(WORDS):
                words[i] = (words[i] + subkeys[s][i]) & 0xFFFFFFFFFFFFFFFF
            s += 1
        for i in range(8):
            rc = ROTATION_CONSTANTS[round][i]
            words[i], words[i+8] = mix(words[i], words[i+8], rc)
        words = words[4:] + words[:4]  # Permute
    return struct.pack("<16Q", *words)

def threefish_decrypt_block(ciphertext, key, tweak):
    subkeys = generate_subkeys(key, tweak)
    words = list(struct.unpack("<16Q", ciphertext))
    s = (ROUNDS // 4)
    for round in reversed(range(ROUNDS)):
        words = words[-4:] + words[:-4]  # Inverse permute
        for i in reversed(range(8)):
            rc = ROTATION_CONSTANTS[round][i]
            words[i], words[i+8] = inv_mix(words[i], words[i+8], rc)
        if (round) % 4 == 0:
            s -= 1
            for i in range(WORDS):
                words[i] = (words[i] - subkeys[s][i]) & 0xFFFFFFFFFFFFFFFF
    return struct.pack("<16Q", *words)

# ======================== ORIGINAL CODE (WITH PADDING FIXES) ========================
def generate_ecdh_keys():
    """Generate and store ECDH key pair"""
    private_key = ec.generate_private_key(ec.SECP384R1())
    with open(ECDH_PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(ECDH_PUBLIC_KEY_FILE, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_ecdh_private_key():
    with open(ECDH_PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_peer_public_key():
    root = tk.Tk()
    root.withdraw()
    key_file = filedialog.askopenfilename(title="Select Peer's Public Key")
    with open(key_file, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def compute_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=192,
        salt=None,
        info=b'Threefish-1024 Key Derivation',
    ).derive(shared_key)
    with open(SHARED_SECRET_FILE, "wb") as f:
        f.write(derived_key)

def get_encryption_keys():
    with open(SHARED_SECRET_FILE, "rb") as f:
        secret = f.read()
    return secret[:128], secret[128:192]

def encrypt_file(input_file, output_file, key, hmac_key):
    file_size = os.path.getsize(input_file)
    tweak = (int.from_bytes(os.urandom(8), 'little'), int.from_bytes(os.urandom(8), 'little'))
    tweak_bytes = struct.pack("<2Q", *tweak)
    hmac_calculator = hmac.new(hmac_key, digestmod=hashlib.sha256)
    
    start_time = time.time()
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(tweak_bytes)
        f_out.write(struct.pack("<Q", file_size))
        processed = 0
        
        while True:
            chunk = f_in.read(BLOCK_SIZE)
            if not chunk:
                break
            processed += len(chunk)
            # PKCS#7 Padding
            if len(chunk) < BLOCK_SIZE or processed == file_size:
                pad_len = BLOCK_SIZE - len(chunk)
                chunk += bytes([pad_len] * pad_len)
            encrypted = threefish_encrypt_block(chunk, key, tweak_bytes)
            f_out.write(encrypted)
            hmac_calculator.update(encrypted)
            show_progress(processed, file_size, start_time, "Encrypting")
        
        f_out.write(hmac_calculator.digest())
    
    elapsed_time = time.time() - start_time
    print(f"\nEncryption completed in {format_time(elapsed_time)}.")

def decrypt_file(input_file, key, hmac_key):
    start_time = time.time()
    
    with open(input_file, 'rb') as f_in:
        tweak_bytes = f_in.read(16)
        if len(tweak_bytes) != 16:
            print("Error: Invalid tweak size. File may be corrupted.")
            return
        
        tweak = struct.unpack("<2Q", tweak_bytes)
        file_size = struct.unpack("<Q", f_in.read(8))[0]
        encrypted_data = f_in.read()
        hmac_stored = encrypted_data[-32:]
        encrypted_data = encrypted_data[:-32]
        
        hmac_calculator = hmac.new(hmac_key, encrypted_data, hashlib.sha256)
        computed_hmac = hmac_calculator.digest()
        
        if computed_hmac != hmac_stored:
            print("HMAC verification failed. File may be tampered with.")
            return
        
        processed = 0
        decrypted_data = bytearray()
        
        for i in range(0, len(encrypted_data), BLOCK_SIZE):
            chunk = encrypted_data[i:i+BLOCK_SIZE]
            decrypted = threefish_decrypt_block(chunk, key, tweak_bytes)
            decrypted_data.extend(decrypted)
            processed += len(chunk)
            show_progress(processed, file_size, start_time, "Decrypting")
        
        # Remove PKCS#7 padding
        if file_size < len(decrypted_data):
            pad_len = decrypted_data[-1]
            if pad_len < 1 or pad_len > BLOCK_SIZE:
                print("Invalid padding detected. File corrupted.")
                return
            decrypted_data = decrypted_data[:file_size]
        
        output_file = os.path.join(
            os.path.dirname(input_file),
            "dec_" + os.path.basename(input_file).replace(".enc", "")
        )
        with open(output_file, 'wb') as f_out:
            f_out.write(decrypted_data[:file_size])
    
    elapsed_time = time.time() - start_time
    print(f"\nDecryption completed in {format_time(elapsed_time)}.")
    print(f"File saved as: {output_file}")

def select_file():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename()

if __name__ == "__main__":
    while True:
        print("\nSelect operation:")
        print("1. Generate ECDH keys")
        print("2. Encrypt file")
        print("3. Decrypt file")
        print("4. Exit")
        choice = input("Choice (1/2/3/4): ").strip()

        if choice == "1":
            generate_ecdh_keys()
            print("ECDH key pair generated successfully.")
        
        elif choice == "2":
            if not (os.path.exists(ECDH_PRIVATE_KEY_FILE) and os.path.exists(ECDH_PUBLIC_KEY_FILE)):
                print("Error: Generate ECDH keys first using option 1")
                continue
            try:
                private_key = load_ecdh_private_key()
                print("Select the recipient's public key:")
                peer_public_key = load_peer_public_key()
                compute_shared_secret(private_key, peer_public_key)
                encryption_key, hmac_key = get_encryption_keys()
                input_file = select_file()
                if not input_file:
                    continue
                encrypt_file(input_file, input_file + ".enc", encryption_key, hmac_key)
            except Exception as e:
                print(f"Error during encryption: {str(e)}")
        
        elif choice == "3":
            if not (os.path.exists(ECDH_PRIVATE_KEY_FILE) and os.path.exists(ECDH_PUBLIC_KEY_FILE)):
                print("Error: Generate ECDH keys first using option 1")
                continue
            try:
                private_key = load_ecdh_private_key()
                print("Select the sender's public key:")
                peer_public_key = load_peer_public_key()
                compute_shared_secret(private_key, peer_public_key)
                encryption_key, hmac_key = get_encryption_keys()
                encrypted_file = select_file()
                if not encrypted_file:
                    continue
                decrypt_file(encrypted_file, encryption_key, hmac_key)
            except Exception as e:
                print(f"Error during decryption: {str(e)}")
        
        elif choice == "4":
            print("Exiting program.")
            break
        
        else:
            print("Invalid choice. Please enter 1-4.")