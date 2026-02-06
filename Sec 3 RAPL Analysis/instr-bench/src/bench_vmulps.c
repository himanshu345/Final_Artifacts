/* bench_vmulps.c – one 128-bit single-precision vector multiply per iteration
 *
 * Build : picked up automatically by ‘make’
 * Usage : ../bin/bench_vmulps <iterations>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <immintrin.h>
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

       /* --- constants & scratch ------------------------------------------------ */
    __m128 v1 = _mm_set_ps(1.0f, 2.0f, 3.0f, 4.0f);
    const __m128 v2 = _mm_set_ps(5.0f, 6.0f, 7.0f, 8.0f);
    static volatile float sink;           /* forces a side-effect */

    for (uint64_t i = 0; i < iters; i++) {
        v1 = _mm_mul_ps(v1, v2);          /* vmulps */
        sink += _mm_cvtss_f32(v1);        /* write every iter → no optimisation */
    }
    return 0;
}

