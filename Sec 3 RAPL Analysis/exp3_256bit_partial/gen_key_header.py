import subprocess
import os

def generate_512_key():
    print("[+] Generating 512-bit RSA key (Smallest allowed by modern OpenSSL)...")
    # Generate 512-bit key and convert to DER
    try:
        cmd = "openssl genrsa 512 2>/dev/null | openssl rsa -outform DER 2>/dev/null"
        return subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError:
        print("[!] Error: OpenSSL still refuses 512 bits. Trying 1024 bits...")
        cmd = "openssl genrsa 1024 2>/dev/null | openssl rsa -outform DER 2>/dev/null"
        return subprocess.check_output(cmd, shell=True)

def parse_der(der_bytes):
    pos = 0
    def read_len():
        nonlocal pos
        l = der_bytes[pos]; pos += 1
        if l & 0x80:
            n_bytes = l & 0x7f
            l = int.from_bytes(der_bytes[pos:pos+n_bytes], 'big')
            pos += n_bytes
        return l
    
    if der_bytes[pos] != 0x30: raise ValueError("Not a DER sequence")
    pos += 1; read_len() # Skip sequence header
    
    components = []
    for _ in range(9): # version + 8 components
        if der_bytes[pos] != 0x02: raise ValueError("Expected Integer tag")
        pos += 1; length = read_len()
        val = der_bytes[pos:pos+length]
        pos += length
        if val[0] == 0x00 and len(val) > 1: val = val[1:]
        components.append(val)
    
    return {"n": components[1], "e": components[2], "d": components[3]}

def write_header(data):
    with open("key.h", "w") as f:
        f.write("#ifndef RSA_KEY_H\n#define RSA_KEY_H\n\n")
        for name in ["n", "e", "d"]:
            val = data[name]
            f.write(f"static const unsigned char rsa_{name}[] = {{ {', '.join([f'0x{b:02x}' for b in val])} }};\n")
            f.write(f"static const size_t rsa_{name}_len = {len(val)};\n\n")
        f.write("#endif\n")

if __name__ == "__main__":
    der = generate_512_key()
    data = parse_der(der)
    write_header(data)
    print(f"[+] Created key.h ({len(data['n'])*8}-bit)")