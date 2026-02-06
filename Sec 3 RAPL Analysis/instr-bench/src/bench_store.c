/* bench_store.c – hammer one core with a single 64-bit store per iteration
 *
 * Build : gcc -O2 -march=native -o ../bin/bench_store bench_store.c
 * Usage : ../bin/bench_store <iterations>
 *
 * Instruction executed:
 *     movq %rax, (%rsi)
 *
 * Matches the “store” micro-benchmark in the PLATYPUS paper.
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

    /* pin to CPU 0 to minimise scheduler noise */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    /* prepare a 64-byte dummy buffer aligned to a cacheline */
    static uint64_t __attribute__((aligned(64))) buf[8] = {0};

    register uint64_t rax asm("rax") = 0xCAFEBABECAFEBABEULL;
    register uint64_t rsi asm("rsi") = (uint64_t)buf;

    for (uint64_t i = 0; i < iters; i++) {
        asm volatile ("movq %%rax, (%%rsi)"
                      :
                      : "a"(rax), "S"(rsi)
                      : "memory");
    }
    return 0;
}
