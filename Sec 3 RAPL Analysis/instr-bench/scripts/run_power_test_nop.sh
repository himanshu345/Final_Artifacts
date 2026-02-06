#!/usr/bin/env bash
# run_power_test_nop.sh – measure energy for bench_nop

RAPL="/sys/class/powercap/intel-rapl:0/energy_uj"
ITERS=15000000000                      # 15 billion, ~5 s on your CPU

# read counter before the loop
E0=$(cat "$RAPL")
T0=$(date +%s%N)

./bench_nop "$ITERS"

# read counter after the loop
E1=$(cat "$RAPL")
T1=$(date +%s%N)

echo "iterations  : $ITERS"
echo "energy (µJ) : $((E1 - E0))"
echo "elapsed (ns): $((T1 - T0))"
