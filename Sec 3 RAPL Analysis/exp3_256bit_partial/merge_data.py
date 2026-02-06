import pandas as pd
import os
import glob

def merge_datasets():
    combined_dir = "data/combined_research"
    if not os.path.exists(combined_dir):
        os.makedirs(combined_dir)

    csv_files = glob.glob("data/exp3_*/correlation.csv")
    
    if not csv_files:
        print("No datasets found to merge!")
        return

    print(f"[+] Found {len(csv_files)} potential datasets. Validating...")

    all_dfs = []
    for f in csv_files:
        # Skip files that are empty (0 bytes)
        if os.path.getsize(f) == 0:
            print(f"  [!] Skipping {f}: File is empty.")
            continue
            
        try:
            df = pd.read_csv(f)
            if df.empty:
                print(f"  [!] Skipping {f}: No data rows found.")
                continue
            
            df['source_run'] = os.path.basename(os.path.dirname(f))
            all_dfs.append(df)
            print(f"  [+] Loaded {len(df)} traces from {f}")
        except Exception as e:
            print(f"  [!] Skipping {f}: Error reading file ({e})")

    if not all_dfs:
        print("No valid data found to merge!")
        return

    # 3. Concatenate and save
    master_df = pd.concat(all_dfs, ignore_index=True)
    master_path = os.path.join(combined_dir, "master_correlation.csv")
    master_df.to_csv(master_path, index=False)

    print(f"\n[+] SUCCESS: Merged {len(master_df)} total traces into {master_path}")

if __name__ == "__main__":
    merge_datasets()