import pandas as pd
import numpy as np
from scipy.stats import pearsonr
import re
import os

# --- 1. SETUP & PARAMETERS ---
def get_modulus_and_key(filename):
    with open(filename, 'r') as f:
        content = f.read()
    def extract(var):
        match = re.search(rf"rsa_{var}\[\] = \{{ (.*?) \}};", content, re.DOTALL)
        hex_vals = match.group(1).replace("0x", "").replace(",", "").replace(" ", "").replace("\n", "")
        return int(hex_vals, 16)
    n = extract('n')
    d = extract('d')
    d_bin = bin(d)[2:]
    return n, d_bin[:3]

N, REAL_BITS = get_modulus_and_key('key.h')
DATA_PATH = "data/combined_research/master_correlation.csv"

# --- 2. MODELING ---
def model_guess(msg_hex, guess_int, modulus):
    msg_int = int(msg_hex, 16)
    R = pow(2, 512, modulus) # Montgomery constant for 512-bit
    # Intermediate = M^guess mod N
    res_standard = pow(msg_int, guess_int, modulus)
    # Convert to Montgomery form (internal register state)
    res_mont = (res_standard * R) % modulus
    return bin(res_mont).count('1')

# --- 3. EXECUTION ---
if not os.path.exists(DATA_PATH):
    print(f"Error: {DATA_PATH} not found. Run merge_runs.py first.")
    exit()

df = pd.read_csv(DATA_PATH)
print(f"[+] Attacking combined dataset with {len(df)} traces...")

results = []
for guess in range(8):
    # Progress indicator
    print(f"  Evaluating Guess {format(guess, '03b')}... ", end='', flush=True)
    
    hws = df['msg_hex'].apply(lambda x: model_guess(x, guess, N))
    r, p = pearsonr(hws, df['energy_uj'])
    
    results.append({'guess': format(guess, '03b'), 'r': r, 'p': p})
    print(f"r = {r:+.6f}, p = {p:.2e}")

# --- 4. REPORT ---
res_df = pd.DataFrame(results)
# We look for the maximum ABSOLUTE correlation
winner = res_df.iloc[res_df['r'].abs().idxmax()]

print("\n================= COMBINED ATTACK REPORT =================")
print(f"Total Traces Analyzed: {len(df)}")
print(f"Actual Key Bits:       {REAL_BITS}")
print(f"Attacker's Best Guess: {winner['guess']} (r={winner['r']:.6f})")
print(f"Confidence (P-Value):  {winner['p']:.2e}")
print("----------------------------------------------------------")

if winner['guess'] == REAL_BITS:
    print("RESULT: SUCCESS! Increased sample size revealed the key.")
else:
    # Check if the correct bits are at least in the top 2
    sorted_res = res_df.reindex(res_df['r'].abs().sort_values(ascending=False).index)
    rank = sorted_res.index[sorted_res['guess'] == REAL_BITS].tolist()[0] + 1
    print(f"RESULT: FAILURE. Correct bits ranked #{rank} out of 8.")
print("==========================================================")