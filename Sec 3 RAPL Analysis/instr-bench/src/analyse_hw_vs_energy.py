
#!/usr/bin/env python3
"""
plot_hw_vs_energy.py
Read hw_energy.log, convert µJ → pJ per instruction,
and plot Energy (pJ) on the X-axis vs. operand Hamming weight (bits) on the Y-axis.
"""

import re, pathlib, numpy as np, matplotlib.pyplot as plt

LOG_FILE = pathlib.Path("hw_energy.log")
ITERS    = 15_000_000_000          # iterations used in run_power_test.sh

pat_operand = re.compile(r"operand\s*:\s*(0x[0-9a-fA-F]+)")
pat_energy  = re.compile(r"energy \(µJ\)\s*:\s*(\d+)")

hw_bits, energy_pJ = [], []

with LOG_FILE.open() as f:
    lines = f.readlines()

for i in range(0, len(lines), 4):
    op  = int(pat_operand.search(lines[i + 1]).group(1), 16)
    ene = int(pat_energy .search(lines[i + 2]).group(1)) * 1e-6  # µJ → J

    hw_bits.append(bin(op).count("1"))
    energy_pJ.append((ene / ITERS) * 1e12)                       # J → pJ

# --- plot -------------------------------------------------------
plt.figure(figsize=(6, 4))
plt.scatter(energy_pJ, hw_bits, s=60, color="tab:blue")
plt.xlabel("Energy per instruction (pJ)")
plt.ylabel("Operand Hamming weight (bits)")
plt.title("PLATYPUS – Experiment 1 (raw points)")
plt.grid(ls="--", alpha=0.4)
plt.tight_layout()
plt.savefig("hw_vs_energy_raw.png", dpi=150)
plt.show()
