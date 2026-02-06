import subprocess

def get_valid_modulus():
    print("[+] Generating 3072-bit RSA modulus...")
    cmd = "openssl genrsa 3072 | openssl rsa -text -noout"
    out = subprocess.check_output(cmd, shell=True).decode()
    start_marker = "modulus:"
    lines = out.split('\n')
    hex_str = ""
    capture = False
    for line in lines:
        if start_marker in line:
            capture = True; continue
        if capture and line.startswith("    "):
            hex_str += line.replace(":", "").strip()
        elif capture: break
    if hex_str.startswith("00"): hex_str = hex_str[2:]
    return hex_str

def write_header(n_hex):
    # Base exponent: Just MSB and LSB set (3072-bit odd number)
    base_d = (1 << 3071) | 1
    
    with open("keys.h", "w") as f:
        f.write("#ifndef KEYS_H\n#define KEYS_H\n\n")
        f.write(f"static const unsigned char rsa_n[] = {{ {', '.join([f'0x{n_hex[i:i+2]}' for i in range(0, len(n_hex), 2)])} }};\n")
        f.write(f"static const size_t rsa_n_len = {len(n_hex)//2};\n\n")
        
        f.write("struct ExpKey { const char* label; int bit_flipped; size_t len; unsigned char data[384]; };\n\n")
        f.write("static const struct ExpKey exp_keys[] = {\n")
        
        # Generate 16 keys: Base key + 15 bit flips (Bit 1 to Bit 15)
        # We skip Bit 0 (LSB) and Bit 3071 (MSB) as they must remain 1.
        for bit_pos in range(0, 16):
            if bit_pos == 0:
                current_d = base_d
                label = "Base_Key"
            else:
                current_d = base_d | (1 << bit_pos)
                label = f"Bit_Flip_{bit_pos}"
            
            h = hex(current_d)[2:]
            if len(h) % 2 != 0: h = "0" + h
            bytes_str = ", ".join([f"0x{h[i:i+2]}" for i in range(0, len(h), 2)])
            f.write(f'    {{ "{label}", {bit_pos}, {len(h)//2}, {{ {bytes_str} }} }},\n')
            
        f.write("};\n\n#endif")

if __name__ == "__main__":
    n = get_valid_modulus()
    write_header(n)
    print("[+] Successfully generated keys.h with 16 bit-flip variants.")