
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
import pycuda.driver as drv
import numpy as np  # Add this
import pycuda.autoinit  # Add this (after pycuda.driver import)
import atexit
import time

#time 
def format_time(seconds):
    """Convert seconds to HH:MM:SS format."""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def show_progress(current, total, message, start_time):
    """Display progress bar with time elapsed and estimated remaining."""
    elapsed = time.time() - start_time
    if current == 0:
        elapsed_str = format_time(0)
        remaining_str = format_time(0)
        percent = 0.0
    else:
        percent = (current / total) * 100
        elapsed_str = format_time(elapsed)
        if elapsed > 0:
            estimated_total = (elapsed / current) * total
            remaining = estimated_total - elapsed
            remaining_str = format_time(remaining)
        else:
            remaining_str = "Calculating..."
    
    # Progress bar visualization
    bar_length = 30
    filled = int(bar_length * current // total)
    bar = '█' * filled + '-' * (bar_length - filled)
    
    sys.stdout.write(
        f"\r{message}: |{bar}| {percent:.1f}% "
        f"[Elapsed: {elapsed_str}, Remaining: {remaining_str}]"
    )
    sys.stdout.flush()


# Load precompiled CUDA kernel from .ptx file
with open(r'C:\Users\amalj\Desktop\test\ts3 Cuda\B\threefish.ptx', 'rb') as f:
    ptx_code = f.read()
mod = drv.module_from_buffer(ptx_code)

# Get encryption and decryption kernels
encrypt_kernel = mod.get_function("_Z24threefish_encrypt_kernelPyiS_i")
decrypt_kernel = mod.get_function("_Z24threefish_decrypt_kernelPyiS_i")

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


# Fix padding logic
def encrypt_file(input_file, output_file, key, hmac_key):
    start_time = time.time()
    file_size = os.path.getsize(input_file)
    tweak = (int.from_bytes(os.urandom(8), 'little'), 
            int.from_bytes(os.urandom(8), 'little'))
    tweak_bytes = struct.pack("<2Q", *tweak)
    
    # Read and pad the file
    with open(input_file, 'rb') as f_in:
        plaintext = f_in.read()
    
    pad_len = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    if pad_len == BLOCK_SIZE:
        pad_len = 0
    plaintext += bytes([pad_len] * pad_len)
    
    # Generate subkeys
    subkeys = generate_subkeys(key, tweak_bytes)
    
    # Encrypt in batches with progress
    encrypted_blocks = threefish_gpu_encrypt_blocks(plaintext, subkeys, batch_size=512)
    
    # Write output
    with open(output_file, 'wb') as f_out:
        f_out.write(tweak_bytes)
        f_out.write(struct.pack("<Q", file_size))
        f_out.write(encrypted_blocks)
        
        # Calculate HMAC
        hmac_calculator = hmac.new(hmac_key, encrypted_blocks, hashlib.sha256)
        f_out.write(hmac_calculator.digest())
    
    # After encryption completes
    total_time = time.time() - start_time
    print(f"\nEncryption completed in {format_time(total_time)}.")


def threefish_gpu_encrypt_blocks(all_blocks, subkeys, batch_size=1024):
    """Encrypt blocks in batches to show progress"""
    start_time = time.time()  # Track start time
    total_bytes = len(all_blocks)
    total_blocks = total_bytes // BLOCK_SIZE
    encrypted_data = bytearray()
    
    # Flatten subkeys and copy to GPU once
    subkeys_np = np.array(subkeys, dtype=np.uint64).flatten()
    subkeys_gpu = drv.mem_alloc(subkeys_np.nbytes)
    drv.memcpy_htod(subkeys_gpu, subkeys_np)
    
    for batch_start in range(0, total_blocks, batch_size):
        # Calculate current batch size
        current_batch_size = min(batch_size, total_blocks - batch_start)
        batch_bytes = current_batch_size * BLOCK_SIZE
        
        # Extract batch data
        start = batch_start * BLOCK_SIZE
        end = start + batch_bytes
        batch = all_blocks[start:end]
        
        # Copy batch to GPU
        blocks_np = np.frombuffer(batch, dtype=np.uint64)
        blocks_gpu = drv.mem_alloc(blocks_np.nbytes)
        drv.memcpy_htod(blocks_gpu, blocks_np)
        
        # Launch kernel for this batch
        threads_per_block = 256
        grid_size = (current_batch_size + threads_per_block - 1) // threads_per_block
        
        encrypt_kernel(
            blocks_gpu,
            np.int32(current_batch_size),
            subkeys_gpu,
            np.int32(len(subkeys_np)),
            block=(threads_per_block, 1, 1),
            grid=(grid_size, 1)
        )
        
        # Copy back and accumulate results
        encrypted_batch = np.empty_like(blocks_np)
        drv.memcpy_dtoh(encrypted_batch, blocks_gpu)
        encrypted_data.extend(encrypted_batch.tobytes())
        
        # Free GPU memory for this batch
        blocks_gpu.free()
        
        # Update progress
        processed = batch_start + current_batch_size
        show_progress(processed, total_blocks, "Encrypting", start_time)
    
    # Free subkeys GPU memory
    subkeys_gpu.free()
    return bytes(encrypted_data)

def threefish_gpu_decrypt_blocks(all_blocks, subkeys, batch_size=1024):
    """Decrypt blocks in batches to show progress"""
    start_time = time.time()  # Track start time
    total_bytes = len(all_blocks)
    total_blocks = total_bytes // BLOCK_SIZE
    decrypted_data = bytearray()
    
    # Flatten subkeys and copy to GPU once
    subkeys_np = np.array(subkeys, dtype=np.uint64).flatten()
    subkeys_gpu = drv.mem_alloc(subkeys_np.nbytes)
    drv.memcpy_htod(subkeys_gpu, subkeys_np)
    
    for batch_start in range(0, total_blocks, batch_size):
        # Calculate current batch size
        current_batch_size = min(batch_size, total_blocks - batch_start)
        batch_bytes = current_batch_size * BLOCK_SIZE
        
        # Extract batch data
        start = batch_start * BLOCK_SIZE
        end = start + batch_bytes
        batch = all_blocks[start:end]
        
        # Copy batch to GPU
        blocks_np = np.frombuffer(batch, dtype=np.uint64)
        blocks_gpu = drv.mem_alloc(blocks_np.nbytes)
        drv.memcpy_htod(blocks_gpu, blocks_np)
        
        # Launch kernel for this batch
        threads_per_block = 256
        grid_size = (current_batch_size + threads_per_block - 1) // threads_per_block
        
        decrypt_kernel(
            blocks_gpu,
            np.int32(current_batch_size),
            subkeys_gpu,
            np.int32(len(subkeys_np)),
            block=(threads_per_block, 1, 1),
            grid=(grid_size, 1)
        )
        
        # Copy back and accumulate results
        decrypted_batch = np.empty_like(blocks_np)
        drv.memcpy_dtoh(decrypted_batch, blocks_gpu)
        decrypted_data.extend(decrypted_batch.tobytes())
        
        # Free GPU memory for this batch
        blocks_gpu.free()
        
        # Update progress
        processed = batch_start + current_batch_size
        show_progress(processed, total_blocks, "Decrypting", start_time)
    
    # Free subkeys GPU memory
    subkeys_gpu.free()
    return bytes(decrypted_data)
# In the decrypt_file function, fix padding removal:

def decrypt_file(input_file, key, hmac_key):
    start_time = time.time()
    with open(input_file, 'rb') as f_in:
        tweak_bytes = f_in.read(16)
        tweak = struct.unpack("<2Q", tweak_bytes)
        file_size = struct.unpack("<Q", f_in.read(8))[0]
        encrypted_data = f_in.read()
        hmac_stored = encrypted_data[-32:]
        encrypted_blocks = encrypted_data[:-32]
        
        # Verify HMAC
        hmac_calculator = hmac.new(hmac_key, encrypted_blocks, hashlib.sha256)
        computed_hmac = hmac_calculator.digest()
        if computed_hmac != hmac_stored:
            print("HMAC verification failed!")
            return
        
        # Generate subkeys
        subkeys = generate_subkeys(key, tweak_bytes)
        
        # Decrypt in batches with progress
        decrypted_data = threefish_gpu_decrypt_blocks(encrypted_blocks, subkeys, batch_size=512)
        
        # Remove padding
        pad_len = decrypted_data[-1]
        if pad_len < BLOCK_SIZE:
            decrypted_data = decrypted_data[:-pad_len]
        
        # Save output
        output_file = os.path.join(
            os.path.dirname(input_file),
            "dec_" + os.path.basename(input_file).replace(".enc", "")
        )
        with open(output_file, 'wb') as f_out:
            f_out.write(decrypted_data)
        total_time = time.time() - start_time
        print(f"\nDecryption completed in {format_time(total_time)}.")
            
def select_file():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename()


# Cleanup function
def cleanup_gpu_memory():
    if 'rotation_constants_gpu' in globals():
        rotation_constants_gpu.free()
    if 'blocks_gpu' in globals():
        blocks_gpu.free()
    if 'subkeys_gpu' in globals():
        subkeys_gpu.free()

atexit.register(cleanup_gpu_memory)
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
