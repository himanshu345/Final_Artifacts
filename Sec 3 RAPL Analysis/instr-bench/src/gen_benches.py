#!/usr/bin/env python3
"""
gen_benches.py – create one micro-benchmark source file per mnemonic listed
in extra_mnemonics.txt.  Every file is called  bench_<mnemonic>.c  and
contains a tight loop that executes exactly one instance of that instruction.

Run:
    ./gen_benches.py        # from the src/ directory
"""

import pathlib

TEMPLATE = r'''/* AUTOGEN: bench_{mn}.c – one "{mn_upper}" per iteration */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>

int main(int argc, char **argv)
{{
    if (argc != 2) {{
        fprintf(stderr, "Usage: %s <iterations>\n", argv[0]);
        return 1;
    }}
    uint64_t iters = strtoull(argv[1], NULL, 10);

    /* pin to logical core 0 */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    /* one 64-byte line we may legally touch/flush */
    static char __attribute__((aligned(64))) buf[64] = {{0}};

    /* RAX begins at &buf — safe for every mnemonic, incl. cache ops */
    register uint64_t rax asm("rax") = (uint64_t)buf;

    for (uint64_t i = 0; i < iters; i++) {{
        asm volatile ("{asm_instr}"
                      : "+a"(rax)
                      :
                      : {clobbers});
    }}
    return 0;
}}
'''

# ─── instruction families ──────────────────────────────────────────────
SHIFT_ROT   = {"shl", "shr", "sar", "rol", "ror"}

BINARY_OPS  = {  # two-operand scalar ALU / bit ops
    "xor", "and", "or", "adc",
    "sub", "sbb", "cmp", "test",
    "bsf", "bsr", "popcnt", "lzcnt", "tzcnt",
    "btc", "btr", "bts", "bt",
    "cmovz", "cmovnz"
}

SETCC_OPS   = {"setz", "setnz", "setc", "seta", "setb"}

SSE_2OP     = {"addps", "subps", "mulps", "divps"}          # 2-operand XMM

FENCE_OPS   = {"lfence", "sfence", "mfence"}                 # 0-operand fences

VECTOR_3OP = {                                               # AVX 3-operand
    "vaddps", "vsubps", "vmulps", "vdivps",
    "vaddpd", "vsubpd", "vmulpd", "vdivpd",
    "vpaddd", "vpsubd", "vpmulld",
    "vpand",  "vpor",   "vpxor",
    "vandps", "vmaxps", "vminps"
}

MEM_OPS     = {"clflush", "clflushopt", "prefetcht0"}  # mem-addressed

# ─── generate one C file per mnemonic ──────────────────────────────────
mn_file = pathlib.Path("extra_mnemonics.txt").read_text().splitlines()

for mn in filter(None, (m.strip() for m in mn_file)):
    clobbers = '"cc"'        # default: only flags are touched

    if mn in SHIFT_ROT:
        asm = f"{mn} $1, %%rax"

    elif mn in BINARY_OPS:
        asm = f"{mn} %%rax, %%rax"

    elif mn in SETCC_OPS:
        asm = f"{mn} %%al"

    elif mn == "lea":
        asm = "leaq (%%rax), %%rax"

    elif mn == "mul":            # unsigned 64-bit multiply: RDX is written
        asm = "mulq %%rax"
        clobbers = '"rdx","cc"'

    elif mn == "imul":           # 32-bit variant for diversity
        asm = "imull %%eax, %%eax"

    elif mn in SSE_2OP:          # 128-bit, 2-operand SSE
        asm = f"{mn} %%xmm0, %%xmm1"

    elif mn in FENCE_OPS:
        asm = mn                 # e.g.  "lfence"
        clobbers = '"memory","cc"'

    elif mn in VECTOR_3OP:       # 128-bit, 3-operand AVX form
        asm = f"{mn} %%xmm0, %%xmm1, %%xmm1"

    elif mn in MEM_OPS:
        asm = f"{mn} (%%rax)"
        clobbers = '"memory","cc"'

    else:                        # fall-back: assume unary reg instruction
        asm = f"{mn} %%rax"

    code = TEMPLATE.format(
        mn=mn,
        mn_upper=mn.upper(),
        asm_instr=asm,
        clobbers=clobbers
    )
    pathlib.Path(f"bench_{mn}.c").write_text(code)
    print(f"generated bench_{mn}.c")
