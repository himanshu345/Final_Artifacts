#!/usr/bin/env bash
# measure_loop.sh – generic RAPL sampler
# Usage:
#   sudo ./measure_loop.sh <binary> <iterations> <label> [extra args]   
#
# A CSV row is appended to ../data/loop_energy.csv with:
#   label,iterations,energy_uJ,elapsed_ns,extra_args                    

set -e

if [[ $# -lt 3 ]]; then
  echo "Usage: sudo $0 <binary> <iterations> <label> [extra args]"
  exit 1
fi

BIN="../bin/$1"
ITER="$2"
LABEL="$3"
shift 3                               # keep any remaining parameters  
EXTRA_ARGS="$*"                        # store as one string            

RAPL="/sys/class/powercap/intel-rapl:0/energy_uj"
LOG="../data/loop_energy.csv"

# add header the first time
[[ -f $LOG ]] || echo "label,iterations,energy_uJ,elapsed_ns,extra_args" > "$LOG"

E0=$(cat "$RAPL")
T0=$(date +%s%N)

"$BIN" "$ITER" $EXTRA_ARGS            # forward extra args             

E1=$(cat "$RAPL")
T1=$(date +%s%N)

echo "$LABEL,$ITER,$((E1-E0)),$((T1-T0)),$EXTRA_ARGS" >> "$LOG"
echo "✓ $LABEL  →  $((E1-E0)) µJ   in  $((T1-T0)) ns"
