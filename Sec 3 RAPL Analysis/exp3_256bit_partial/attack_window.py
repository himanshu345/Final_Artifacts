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
    return n, d_bin[:3], d_bin[3:6] # Modulus, Window 1 (Known), Window 2 (Target)

N, KNOWN_BITS, TARGET_BITS = get_modulus_and_key('key.h')
latest_dir = sorted([d for d in os.listdir('data') if d.startswith('exp3_')])[-1]
df = pd.read_csv(os.path.join('data', latest_dir, 'correlation.csv'))


# --- 2. DATA CLEANING (3-SIGMA OUTLIER REMOVAL) ---
# print(f"[+] Loading dataset from {DATA_PATH}...")
# df = pd.read_csv(DATA_PATH)
original_count = len(df)

mean_e = df['energy_uj'].mean()
std_e = df['energy_uj'].std()
cutoff = std_e * 3

# Filter: Keep only data within 3 standard deviations
df = df[(df['energy_uj'] > mean_e - cutoff) & (df['energy_uj'] < mean_e + cutoff)]
removed = original_count - len(df)

print(f"[+] Outlier Removal Summary:")
print(f"    Mean: {mean_e:.2f} uJ, StdDev: {std_e:.2f} uJ")
print(f"    Removed {removed} outliers ({removed/original_count*100:.2f}%)")
print(f"    Remaining traces: {len(df)}")

# --- 3. MODELING ---
def model_guess(msg_hex, known_bits_str, guess_int, modulus):
    msg_int = int(msg_hex, 16)
    R = pow(2, 512, modulus)
    
    # Combine Window 1 (Known) + Window 2 (Guess)
    full_guess_str = known_bits_str + format(guess_int, '03b')
    full_guess_int = int(full_guess_str, 2)
    
    # Montgomery Accumulator Model
    res_standard = pow(msg_int, full_guess_int, modulus)
    res_mont = (res_standard * R) % modulus
    return bin(res_mont).count('1')

# --- 4. THE ATTACK ---
print(f"\n[+] Attacking Window 2 (Actual Bits: {TARGET_BITS})...")
results = []

for guess in range(8):
    guess_str = format(guess, '03b')
    hws = df['msg_hex'].apply(lambda x: model_guess(x, KNOWN_BITS, guess, N))
    r, p = pearsonr(hws, df['energy_uj'])
    
    results.append({
        'guess': guess_str,
        'r': r,
        'abs_r': abs(r),
        'p': p
    })
    print(f"  Guess {guess_str} | r = {r:+.6f} | |r| = {abs(r):.6f} | p = {p:.2e}")

# --- 5. RESULTS ---
res_df = pd.DataFrame(results).sort_values(by='abs_r', ascending=False)
winner = res_df.iloc[0]

print("\n================= REFINED ATTACK REPORT =================")
print(f"Winner:      {winner['guess']} (|r|={winner['abs_r']:.6f})")
print(f"Actual Bits: {TARGET_BITS}")
print("---------------------------------------------------------")

if winner['guess'] == TARGET_BITS:
    print("RESULT: SUCCESS! Outlier removal and |r| ranking recovered the key.")
else:
    # Find the rank of the correct guess
    rank = res_df.reset_index().index[res_df['guess'] == TARGET_BITS].tolist()[0] + 1
    print(f"RESULT: FAILURE. Correct bits ranked #{rank} out of 8.")
    print(f"Hint: If |r| values are very close, you need more traces.")
print("=========================================================")