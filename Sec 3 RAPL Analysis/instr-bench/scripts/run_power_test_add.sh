#!/usr/bin/env bash
# run_power_test_add.sh – measure package energy for bench_add

RAPL="/sys/class/powercap/intel-rapl:0/energy_uj"
ITERS=15000000000                     # 15 000 000 000 iterations (~5 s)

# ----- read counter before the loop -----
E0=$(cat "$RAPL")
T0=$(date +%s%N)

../bin/bench_add "$ITERS"

# ----- read counter after the loop -----
E1=$(cat "$RAPL")
T1=$(date +%s%N)

echo "iterations  : $ITERS"
echo "energy (µJ) : $((E1 - E0))"
echo "elapsed (ns): $((T1 - T0))"
