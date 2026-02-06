"""
plot_energy.py – very small helper that draws a line chart of the
measured package-energy for different operand Hamming weights.

Run from the terminal:
    python3 plot_energy.py
"""

import matplotlib.pyplot as plt

# ─── raw data you measured ──────────────────────────────────────────
hamming = [0, 16, 32, 48, 64]                   # bits set
energy  = [35325166, 35783416, 35935638, 36105804, 36368071]  # µJ

# ─── basic line plot ────────────────────────────────────────────────
plt.figure(figsize=(6, 4))
plt.plot(energy, hamming, marker='o')
plt.title('Energy Consumption vs. Hamming Weight')
plt.xlabel('Energy (uJ)')
plt.ylabel('Hamming Weight')
plt.grid(True)
plt.tight_layout()
plt.show()
