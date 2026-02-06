import pandas as pd
import numpy as np
from scipy.stats import pearsonr
import re
import os

# --- 1. RSA SETUP ---
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
    return n, d_bin[:3], d_bin[3:6] # N, Window 1 (Known), Window 2 (Target)

N, KNOWN_BITS, TARGET_BITS = get_params('key.h')

def model_guess(msg_hex, known_bits_str, guess_int, modulus):
    msg_int = int(msg_hex, 16)
    R = pow(2, 512, modulus)
    full_guess_str = known_bits_str + format(guess_int, '03b')
    res_standard = pow(msg_int, int(full_guess_str, 2), modulus)
    res_mont = (res_standard * R) % modulus
    return bin(res_mont).count('1')

# --- 2. THE CORE ATTACK FUNCTION ---
def perform_attack(df, label):
    print(f"\n>>> ANALYZING: {label} ({len(df)} traces)")
    
    # 3-Sigma Outlier Removal
    mean_e, std_e = df['energy_uj'].mean(), df['energy_uj'].std()
    df = df[(df['energy_uj'] > mean_e - 3*std_e) & (df['energy_uj'] < mean_e + 3*std_e)]
    
    results = []
    for guess in range(8):
        guess_str = format(guess, '03b')
        hws = df['msg_hex'].apply(lambda x: model_guess(x, KNOWN_BITS, guess, N))
        r, p = pearsonr(hws, df['energy_uj'])
        results.append({'guess': guess_str, 'r': r, 'abs_r': abs(r), 'p': p})

    # SORTING LOGIC: Highest |r| where r is negative
    neg_results = [res for res in results if res['r'] < 0]
    
    # Print all for transparency
    for res in sorted(results, key=lambda x: x['abs_r'], reverse=True):
        mark = "*" if res['r'] < 0 else " "
        print(f"  {mark} Guess {res['guess']} | r = {res['r']:+.6f} | |r| = {res['abs_r']:.6f} | p = {res['p']:.2e}")

    if not neg_results:
        print("  [!] No negative correlations found. Picking highest |r| as fallback.")
        winner = max(results, key=lambda x: x['abs_r'])
    else:
        winner = max(neg_results, key=lambda x: x['abs_r'])

    print(f"  RESULT: Best Negative Guess is {winner['guess']} (Actual: {TARGET_BITS})")
    return winner['guess'] == TARGET_BITS, df

# --- 3. MAIN EXECUTION ---
def main():
    dirs = sorted([d for d in os.listdir('data') if d.startswith('exp3_')])
    if len(dirs) < 3:
        print("Error: Need at least 3 runs.")
        return

    target_dirs = dirs[-3:]
    all_dfs = []

    # Individual Attacks
    success_count = 0
    for d in target_dirs:
        df = pd.read_csv(os.path.join('data', d, 'correlation.csv'))
        success, cleaned_df = perform_attack(df, d)
        if success: success_count += 1
        all_dfs.append(cleaned_df)

    # Combined Attack
    print("\n" + "="*60)
    print("FINAL STAGE: COMBINED ANALYSIS (Last 3 Runs)")
    print("="*60)
    master_df = pd.concat(all_dfs, ignore_index=True)
    success, _ = perform_attack(master_df, "COMBINED_MASTER")

    print("\n" + "="*60)
    print(f"SUMMARY: {success_count}/3 individual successes.")
    if success:
        print("COMBINED ATTACK: SUCCESS ✅")
    else:
        print("COMBINED ATTACK: FAILURE ❌")
    print("="*60)

if __name__ == "__main__":
    main()