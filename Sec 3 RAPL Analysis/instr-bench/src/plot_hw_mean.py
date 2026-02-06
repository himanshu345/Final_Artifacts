#!/usr/bin/env python3
import pandas as pd, numpy as np, matplotlib.pyplot as plt

ITERS = 15_000_000_000
df = pd.read_csv("hw_runs.csv")

# convert to pJ per instruction
df["e_pJ"] = df["energy_uJ"] * 1e-6 / ITERS * 1e12

stats = df.groupby("hamming").agg(
    mean_pJ=("e_pJ", "mean"),
    std_pJ =("e_pJ", "std")
).reset_index().sort_values("hamming")

# --- plot ---
plt.errorbar(
    stats["mean_pJ"], stats["hamming"],
    xerr=stats["std_pJ"], fmt="o", capsize=3, color="tab:blue"
)
plt.xlabel("Energy per instruction (pJ)")
plt.ylabel("Operand Hamming weight (bits)")
plt.title("PLATYPUS Exp-1 – Mean ±1σ over {} runs".format(df["run_idx"].max()))
plt.grid(ls="--", alpha=0.4)
plt.tight_layout()
plt.savefig("hw_vs_energy_mean.png", dpi=150)
plt.show()

# quick numeric feedback
slope, _ = np.polyfit(stats["hamming"], stats["mean_pJ"], 1)
print(f"Slope ≈ {slope:.3f} pJ/bit  (should be ~0.04–0.06 pJ/bit)")
