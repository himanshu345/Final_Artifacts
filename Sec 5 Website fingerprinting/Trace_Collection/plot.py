import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load the dataset
csv_filename = "web_power_traces.csv"
df = pd.read_csv(csv_filename)

# Convert columns to numeric
df["Time (ms)"] = pd.to_numeric(df["Time (ms)"])
df["PPD_Power_Diff"] = pd.to_numeric(df["PPD_Power_Diff"])

# Replace 0 values with NaN and use forward fill
df["PPD_Power_Diff"] = df["PPD_Power_Diff"].replace(0, np.nan)
df["PPD_Power_Diff"] = df.groupby("Website")["PPD_Power_Diff"].transform(lambda x: x.ffill())

# Drop remaining NaN values
df.dropna(subset=["PPD_Power_Diff"], inplace=True)

# Get unique websites
websites = df["Website"].unique()
num_websites = len(websites)

# Set up subplots (one row per website)
fig, axes = plt.subplots(num_websites, 1, figsize=(10, 5 * num_websites), sharex=True)

# Define a colormap
colors = plt.cm.viridis(np.linspace(0, 1, num_websites))

# Plot each website in a separate subplot
for i, (website, color) in enumerate(zip(websites, colors)):
    subset = df[df["Website"] == website]
    axes[i].plot(subset["Time (ms)"], subset["PPD_Power_Diff"], color=color, label=website)
    axes[i].set_title(f"Power Trace for {website}", fontsize=12)
    axes[i].set_ylabel("PPD Power Diff")
    axes[i].legend()
    axes[i].grid(True)

# Add common x-label
axes[-1].set_xlabel("Time (ms)")

plt.tight_layout()
plt.show()

