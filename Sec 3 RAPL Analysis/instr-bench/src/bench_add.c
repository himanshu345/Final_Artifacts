/* bench_add.c – hammer the CPU with one 64-bit ADD per iteration
 *
 * Build : gcc -O2 -march=native -o ../bin/bench_add bench_add.c
 * Usage : ../bin/bench_add <iterations>
 *
 * The loop executes:   addq %rax, %rbx
 * (chosen because the PLATYPUS paper evaluates a register-to-register ALU op[1]).
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

    /* pin to core 0 to reduce scheduler noise */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    /* seed registers once */
    register uint64_t rax asm("rax") = 0x1234567812345678ULL;
    register uint64_t rbx asm("rbx") = 0x8765432187654321ULL;

    for (uint64_t i = 0; i < iters; i++) {
        asm volatile ("addq %%rax, %%rbx"
                      : "+b"(rbx)          /* updated output */
                      : "a"(rax)           /* input */
                      : "cc");
    }
    (void)rbx;          /* stop the compiler discarding the loop */
    return 0;
}
