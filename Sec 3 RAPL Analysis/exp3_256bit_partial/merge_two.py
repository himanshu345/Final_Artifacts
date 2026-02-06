import pandas as pd
import os

def merge_latest_two():
    # 1. Find all exp3 folders and sort them chronologically
    dirs = sorted([d for d in os.listdir('data') if d.startswith('exp3_')])
    
    if len(dirs) < 2:
        print("Error: Need at least 2 datasets to merge.")
        return

    # 2. Pick the last two
    target_folders = dirs[-2:]
    print(f"[+] Found two latest runs: {target_folders[0]} and {target_folders[1]}")

    # 3. Load and merge
    all_dfs = []
    for f in target_folders:
        path = os.path.join("data", f, "correlation.csv")
        if os.path.exists(path):
            all_dfs.append(pd.read_csv(path))
    
    merged_df = pd.concat(all_dfs, ignore_index=True)
    
    # 4. Save to a dedicated "latest_merge" folder
    output_dir = "data/merged_latest"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "merged.csv")
    merged_df.to_csv(output_path, index=False)
    
    print(f"[+] SUCCESS: Merged {len(merged_df)} traces into {output_path}")

if __name__ == "__main__":
    merge_latest_two()
