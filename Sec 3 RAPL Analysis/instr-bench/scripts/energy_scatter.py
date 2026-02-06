# energy_scatter.py – load loop_energy.csv and draw a scatter plot
#
# Usage:
#   python3 energy_scatter.py            # displays the plot
#   python3 energy_scatter.py --png out.png   # saves to file instead
#
# The script expects the log at ../data/loop_energy.csv
# (relative to this scripts/ directory).

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def main():
    p = argparse.ArgumentParser(description="Scatter-plot energy per benchmark run")
    p.add_argument("--png", metavar="FILE", help="save figure to PNG instead of showing")
    args = p.parse_args()

    log = Path(__file__).parent / "../data/loop_energy.csv"
    if not log.exists():
        raise SystemExit(f"Log file not found: {log}")

    df = pd.read_csv(log)
    df = df.sort_values("energy_uJ")            # nicer left→right ordering

    labels  = df["label"].tolist()
    energy1  = df["energy_uJ"].tolist()
    energy = []
    for i in energy1:
        energy.append(i/5000000)

    plt.figure(figsize=(14, 8))
    plt.scatter(energy, range(len(labels)), s=40, color="tab:blue")
    plt.yticks(range(len(labels)), labels)
    plt.xlabel("Energy per run (nJ)")
    plt.gca().invert_yaxis()          # top-to-bottom order matches CSV
    plt.title("Micro-benchmark energy – energy on X-axis")
    plt.tight_layout()

    if args.png:
        plt.savefig(args.png, dpi=150)
        print(f"Saved plot → {args.png}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
