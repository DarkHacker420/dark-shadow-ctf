#!/usr/bin/env python3
"""
Weak AES Implementation Challenge
Author: DARK-SHADOW
Points: 150

This challenge demonstrates a weak AES implementation with poor key generation.
Your goal is to decrypt the secret message and find the flag.

Hint: The key might be weaker than you think...
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

def weak_key_generator():
    """
    VULNERABILITY: This function generates a predictable key
    It uses a weak pattern that can be easily guessed
    """
    # Weak key generation - using predictable pattern
    key = b'DARKSHADOWCTF123'  # 16 bytes key
    return key

def encrypt_message(message, key):
    """Encrypt message using AES in ECB mode (another vulnerability!)"""
    # VULNERABILITY: Using ECB mode which is insecure
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad message to be multiple of 16 bytes
    padding_length = 16 - (len(message) % 16)
    padded_message = message + bytes([padding_length] * padding_length)
    
    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    return encrypted

def decrypt_message(encrypted_data, key):
    """Decrypt the encrypted message"""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    padding_length = decrypted[-1]
    return decrypted[:-padding_length]

# Encrypted flag (this is what you need to decrypt)
encrypted_flag = base64.b64decode("YUQ3UjBOZ1lWUjBOZ1k3UjBOZ1lWUjBOZ1k3UjBOZ1lWUjA=")

print("=== Weak AES Implementation Challenge ===")
print(f"Encrypted flag (base64): {base64.b64encode(encrypted_flag).decode()}")
print(f"Encrypted flag (hex): {encrypted_flag.hex()}")
print()
print("Your task:")
print("1. Analyze this weak AES implementation")
print("2. Find the weakness in the key generation")
print("3. Decrypt the encrypted flag")
print("4. Submit the decrypted flag to get points!")
print()
print("Hints:")
print("- The key generator uses a predictable pattern")
print("- Look at the function 'weak_key_generator()'")
print("- The key is exactly 16 bytes long")
print("- Try common patterns like 'DARKSHADOWCTF123'")
print()

# Solution (hidden in comments for educational purposes):
# The key is 'DARKSHADOWCTF123' (16 bytes)
# You can decrypt by running:
# key = b'DARKSHADOWCTF123'
# decrypted = decrypt_message(encrypted_flag, key)
# print(decrypted.decode())

if __name__ == "__main__":
    # Demo encryption (for educational purposes)
    secret_message = b"CTF{w34k_a3s_1mpl3m3nt4t10n}"
    key = weak_key_generator()
    
    print("Demo - Encrypting a message with weak key:")
    encrypted = encrypt_message(secret_message, key)
    print(f"Original: {secret_message}")
    print(f"Key: {key}")
    print(f"Encrypted: {base64.b64encode(encrypted).decode()}")
    
    # Verify decryption works
    decrypted = decrypt_message(encrypted, key)
    print(f"Decrypted: {decrypted}")
    
    print("\n" + "="*50)
    print("Now try to decrypt the challenge flag!")
