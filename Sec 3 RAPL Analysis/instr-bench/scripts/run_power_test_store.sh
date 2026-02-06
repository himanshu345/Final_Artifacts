#!/usr/bin/env bash
# run_power_test_store.sh – measure package energy for bench_store
# ---------------------------------------------------------------
# Runs a 15 000 000 000-iteration store loop and prints:
#   iterations, energy (µJ), elapsed time (ns)

RAPL="/sys/class/powercap/intel-rapl:0/energy_uj"
ITERS=15000000000                    # ~5 s on your CPU

# --- read counter BEFORE loop ---
E0=$(cat "$RAPL")
T0=$(date +%s%N)

../bin/bench_store "$ITERS"

# --- read counter AFTER loop ---
E1=$(cat "$RAPL")
T1=$(date +%s%N)

echo "iterations  : $ITERS"
echo "energy (µJ) : $((E1 - E0))"
echo "elapsed (ns): $((T1 - T0))"
