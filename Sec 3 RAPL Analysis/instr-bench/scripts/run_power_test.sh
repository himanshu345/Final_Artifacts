#!/usr/bin/env bash
# run_power_test.sh – measure package energy for a single bench_mov run
# Usage: sudo ./run_power_test.sh <iterations> <hex_value>

RAPL="/sys/class/powercap/intel-rapl:0/energy_uj"

iters="$1"
value="$2"

if [[ -z "$iters" || -z "$value" ]]; then
  echo "Usage: sudo $0 <iterations> <hex_value>"; exit 1
fi

# read counter before
E0=$(cat "$RAPL")
T0=$(date +%s%N)

./bench_mov "$iters" "$value"

# read counter after
E1=$(cat "$RAPL")
T1=$(date +%s%N)

echo "iterations  : $iters"
echo "operand     : $value"
echo "energy (µJ) : $((E1 - E0))"
echo "elapsed (ns): $((T1 - T0))"
