#!/usr/bin/env bash
# sweep_hw_batch.sh – run each HW pattern $REPEAT times and log to CSV
RAPL="/sys/class/powercap/intel-rapl:0/energy_uj"
ITERS=15000000000
REPEAT=8                 # <- adjust if you want even smoother averages

# 9 patterns, 0 → 64 bits in steps of 8
declare -a OPS=(
  0x0000000000000000
  0x00000000000000FF
  0x000000000000FFFF
  0x0000000000FFFFFF
  0x00000000FFFFFFFF
  0x000000FFFFFFFFFF
  0x0000FFFFFFFFFFFF
  0x00FFFFFFFFFFFFFF
  0xFFFFFFFFFFFFFFFF
)

echo "operand_hex,hamming,run_idx,energy_uJ,elapsed_ns" > hw_runs.csv

for op in "${OPS[@]}"; do
  hw=$(python3 - <<EOF
import sys; print(bin(int("$op",16)).count("1"))
EOF
)
  for ((i=1;i<=REPEAT;i++)); do
    e0=$(cat $RAPL)
    t0=$(date +%s%N)
    ./bench_mov $ITERS $op
    e1=$(cat $RAPL)
    t1=$(date +%s%N)
    echo "$op,$hw,$i,$((e1-e0)),$((t1-t0))" >> hw_runs.csv
    sleep 0.1   # brief pause to desynchronise from RAPL tick
  done
done
