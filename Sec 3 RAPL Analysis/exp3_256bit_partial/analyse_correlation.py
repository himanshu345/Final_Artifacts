import pandas as pd
import numpy as np
from scipy.stats import pearsonr
import matplotlib.pyplot as plt
import re
import os

# --- 1. PARAMETER EXTRACTION ---
def get_key_from_header(filename):
    with open(filename, 'r') as f:
        content = f.read()
    def extract_hex(var_name):
        match = re.search(rf"rsa_{var_name}\[\] = \{{ (.*?) \}};", content, re.DOTALL)
        if not match: return None
        hex_vals = match.group(1).replace("0x", "").replace(",", "").replace(" ", "").replace("\n", "")
        return int(hex_vals, 16)
    return extract_hex('n'), extract_hex('d')

N, D = get_key_from_header('key.h')
STOP_BITS = 9

# --- 2. MONTGOMERY MODEL ---
def get_hamming_weight(n):
    return bin(n).count('1')

def simulate_mbedtls_internal(msg_hex, stop_bits, modulus, priv_exp):
    msg_int = int(msg_hex, 16)
    R = pow(2, 512, modulus)
    
    # 1. Initial Montgomery state
    w1_mont = (msg_int * R) % modulus
    current_x = w1_mont
    
    total_hd = 0
    d_bin = bin(priv_exp)[2:]
    
    # We simulate the first N bits of the exponentiation
    # Every 'Square' and 'Multiply' causes a bit-flip leakage
    for bit in d_bin[1:stop_bits]: # Skip the first bit
        previous_x = current_x
        
        # Square step
        current_x = (current_x * current_x) % modulus # Simplified for model
        total_hd += bin(current_x ^ previous_x).count('1')
        
        if bit == '1':
            previous_x = current_x
            # Multiply step
            current_x = (current_x * w1_mont) % modulus
            total_hd += bin(current_x ^ previous_x).count('1')
            
    return total_hd # This is the Hamming Distance Model

# --- 3. LOAD DATA ---
data_dirs = [d for d in os.listdir('data') if d.startswith('exp3_')]
latest_dir = sorted(data_dirs)[-1]
csv_path = os.path.join('data', latest_dir, 'correlation.csv')

print(f"[+] Analyzing: {latest_dir}")
df = pd.read_csv(csv_path)

# --- 4. APPLY MODELS ---
print("[+] Calculating Standard HW Model...")
df['hw_standard'] = df['msg_hex'].apply(lambda x: get_hamming_weight(pow(int(x, 16), int(bin(D)[2:][:STOP_BITS], 2), N)))

print("[+] Calculating Montgomery HW Model...")
df['hw_montgomery'] = df['msg_hex'].apply(lambda x: simulate_mbedtls_internal(x, STOP_BITS, N, D))

# --- 5. CORRELATION ---
r_std, _ = pearsonr(df['hw_standard'], df['energy_uj'])
r_mont, p_mont = pearsonr(df['hw_montgomery'], df['energy_uj'])

print("\n================= CPA RESEARCH REPORT =================")
print(f"Standard Model Correlation:    {r_std:.4f}")
print(f"Montgomery Model Correlation:  {r_mont:.4f}  <-- Target")
print(f"Montgomery P-Value:            {p_mont:.4e}")
print("-------------------------------------------------------")

# Plot the Montgomery result
plt.figure(figsize=(10, 6))
plt.scatter(df['hw_montgomery'], df['energy_uj'], alpha=0.6, color='green')
plt.title(f'Montgomery HW vs Energy (r={r_mont:.4f})')
plt.xlabel('Hamming Weight (Montgomery Form)')
plt.ylabel('Energy (uJ)')
plt.grid(True)
plt.savefig(os.path.join('data', latest_dir, 'montgomery_correlation.png'))
print(f"[+] Plot saved to data/{latest_dir}/montgomery_correlation.png")