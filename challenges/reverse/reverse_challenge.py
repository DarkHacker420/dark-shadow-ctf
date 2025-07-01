#!/usr/bin/env python3
"""
🔄 REVERSE ENGINEERING CHALLENGE
================================
Analyze this code to find the flag.
"""

import sys

def check_password(password):
    # Obfuscated flag checker
    secret_key = "reverse_me"
    
    if password == secret_key:
        # Hidden flag
        flag_parts = ["CTF{", "r3v3rs3_", "3ng1n33r1ng_", "m4st3r}"]
        return "".join(flag_parts)
    
    return "Access Denied!"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python reverse_challenge.py <password>")
        sys.exit(1)
    
    result = check_password(sys.argv[1])
    print(result)
