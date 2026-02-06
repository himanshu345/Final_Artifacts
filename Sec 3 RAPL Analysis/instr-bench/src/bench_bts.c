/* AUTOGEN: bench_bts.c – one "BTS" per iteration */
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

    /* pin to logical core 0 */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    /* one 64-byte line we may legally touch/flush */
    static char __attribute__((aligned(64))) buf[64] = {0};

    /* RAX begins at &buf — safe for every mnemonic, incl. cache ops */
    register uint64_t rax asm("rax") = (uint64_t)buf;

    for (uint64_t i = 0; i < iters; i++) {
        asm volatile ("bts %%rax, %%rax"
                      : "+a"(rax)
                      :
                      : "cc");
    }
    return 0;
}
