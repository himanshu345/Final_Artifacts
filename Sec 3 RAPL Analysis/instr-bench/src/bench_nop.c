/* bench_nop.c – hammer the CPU with a single “nop” instruction
 *
 * Build : gcc -O2 -march=native -o bench_nop bench_nop.c
 * Usage : ./bench_nop <iterations>
 *
 * Identical structure to bench_mov so we can reuse run_power_test.sh.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <iterations>\n", argv[0]);
        return 1;
    }
    uint64_t iters = strtoull(argv[1], NULL, 10);

    /* pin to core 0 */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    for (uint64_t i = 0; i < iters; i++) {
        asm volatile ("nop");
    }
    return 0;
}
