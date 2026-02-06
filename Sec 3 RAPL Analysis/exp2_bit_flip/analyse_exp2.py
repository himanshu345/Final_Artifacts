import pandas as pd
import glob
import os
import numpy as np
import matplotlib.pyplot as plt

def analyze_exp2_tvla():
    # 1. Find latest summary
    list_of_files = glob.glob('data/exp2_bitflip_*/summary.csv')
    if not list_of_files:
        print("No summary files found.")
        return
    latest_file = max(list_of_files, key=os.path.getctime)
    print(f"Performing TVLA on: {latest_file}")

    # 2. Load data
    df = pd.read_csv(latest_file)
    
    # N is the number of samples per key (from your App.cpp)
    N = 500 

    # 3. Extract Base Key stats
    base_row = df[df['label'] == 'Base_Key'].iloc[0]
    mu_base = base_row['mean_uj']
    std_base = base_row['stddev_uj']

    # 4. Calculate T-Values (Welch's T-Test)
    # Formula: t = (mu1 - mu2) / sqrt((std1^2/N) + (std2^2/N))
    def calculate_t(row):
        mu_flip = row['mean_uj']
        std_flip = row['stddev_uj']
        numerator = abs(mu_base - mu_flip)
        denominator = np.sqrt((std_base**2 / N) + (std_flip**2 / N))
        return numerator / denominator

    df['t_value'] = df.apply(calculate_t, axis=1)
    df['significant'] = df['t_value'] > 4.5

    # 5. Identify Window Size
    # We look for the bit positions where the T-value has a local maximum or a sharp shift
    df['t_diff'] = df['t_value'].diff().abs()
    top_shifts = df.sort_values(by='t_diff', ascending=False).head(3)

    # 6. Print TVLA Report
    print("\n" + "="*75)
    print(f"{'Bit Position':<15} | {'Mean (uJ)':<12} | {'T-Value':<10} | {'Significant?'}")
    print("-" * 75)
    for _, row in df.iterrows():
        sig_str = "YES (PASS)" if row['significant'] else "NO (NOISE)"
        print(f"{row['label']:<15} | {row['mean_uj']:<12.2f} | {row['t_value']:<10.2f} | {sig_str}")
    print("="*75)

    # 7. Objective Conclusion
    passing_bits = df[df['significant'] == True].shape[0]
    print(f"\n[+] RESOLUTION ANALYSIS:")
    print(f"    - {passing_bits}/15 bit flips were statistically detectable (|t| > 4.5).")
    
    if passing_bits > 0:
        print(f"    - CONCLUSION: RAPL has the resolution to detect single-bit changes in SGX.")
    else:
        print(f"    - CONCLUSION: Insufficient resolution. Increase iterations or SIGNS_PER_SAMPLE.")

    print(f"\n[+] WINDOW SIZE INFERENCE:")
    # Look for the first major shift after bit 1
    likely_window = top_shifts[top_shifts['bit_pos'] > 1]['bit_pos'].min()
    print(f"    - Major statistical shift detected at Bit {likely_window}.")
    print(f"    - Inferred mbedTLS Sliding Window Size: {likely_window} bits.")

    # 8. Plotting
    plt.figure(figsize=(10, 6))
    plt.axhline(y=4.5, color='r', linestyle='--', label='TVLA Threshold (4.5)')
    plt.bar(df['label'], df['t_value'], color='skyblue')
    plt.xticks(rotation=45)
    plt.ylabel('T-Value')
    plt.title('TVLA: Statistical Significance of Single Bit Flips')
    plt.legend()
    plt.tight_layout()
    
    plot_path = os.path.dirname(latest_file) + '/tvla_plot.png'
    try:
        plt.savefig(plot_path)
        print(f"\n[+] TVLA Plot saved to {plot_path}")
    except PermissionError:
        print(f"\n[!] Permission denied saving plot. Run: sudo chown -R $USER:$USER data/")

if __name__ == "__main__":
    analyze_exp2_tvla()