#!/usr/bin/env bash
# sweep_all.sh – run every bench_* binary for 15B iterations
# Results are appended to ../data/loop_energy.csv via measure_loop.sh

set -e
ROOT="$(dirname "$0")/.."           # project root
ITER=5000000000
cd "$ROOT/scripts"                  # stay inside scripts/ while running
meas="./measure_loop.sh"            # helper

for exe in ../bin/bench_*; do
    name=$(basename "$exe")
    case "$name" in
        bench_mov)
            sudo "$meas" "$name" $ITER "MOV_HW0"  0x0
            sudo "$meas" "$name" $ITER "MOV_HW64" 0xffffffffffffffff
            ;;
        *)
            # label = uppercase executable name without "bench_"
            label=${name^^}
            label=${label#BENCH_}
            sudo "$meas" "$name" $ITER "$label"
            ;;
    esac
done
