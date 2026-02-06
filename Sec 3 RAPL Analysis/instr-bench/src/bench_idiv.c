/* bench_idiv.c – tight loop with one 64-bit signed DIV per iteration
 *
 * Build : picked up automatically by `make` (see Makefile)
 * Usage : ../bin/bench_idiv <iterations>
 *
 * Instruction executed:
 *     idivq rbx        ; RAX = RDX:RAX / RBX   (quotient in RAX)
 *
 * We preload RDX with 0 to keep the dividend = RAX.
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

    /* pin to logical core 0 */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    /* initialise registers once */
    register uint64_t rax asm("rax") = 0x1234567890abcdefULL;
    register uint64_t rbx asm("rbx") = 0x1111111111111111ULL;   /* divisor */
    register uint64_t rdx asm("rdx") = 0;                       /* high word */

        for (uint64_t i = 0; i < iters; i++) {
        asm volatile (
            "xor %%rdx, %%rdx\n\t"     /* RDX = 0  ->  dividend fits 64 bit   */
            "divq %%rbx"               /* unsigned divide  (quotient in RAX) */
            : "+a"(rax)                /* RAX = quotient (ignored)            */
            : "b"(rbx)                 /* RBX = constant divisor              */
            : "rdx","cc"
        );
    }

    (void)rax;  /* keep compiler from optimising out the loop */
    return 0;
}
