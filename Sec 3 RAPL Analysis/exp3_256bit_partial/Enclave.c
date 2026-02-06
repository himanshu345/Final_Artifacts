#include "Enclave_t.h"
#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"
#include <string.h>

static mbedtls_rsa_context global_rsa;
extern int mbedtls_mpi_stop_bits; // The variable from your modified bignum.c

int ecall_setup_key(const unsigned char* n, size_t n_len, const unsigned char* d, size_t d_len) {
    mbedtls_rsa_init(&global_rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_mpi_read_binary(&global_rsa.N, n, n_len);
    mbedtls_mpi_read_binary(&global_rsa.E, d, d_len); // Public Key Hack: D into E
    global_rsa.len = mbedtls_mpi_size(&global_rsa.N);
    return 0;
}

void ecall_empty_loop(uint32_t iterations) {
    for (volatile uint32_t i = 0; i < iterations; i++) {
        __asm__("nop");
    }
}

int ecall_rsa_partial_benchmark(const unsigned char* msg, size_t msg_len, unsigned char* sig, size_t sig_len, int stop_bits, uint32_t iterations) {
    unsigned char padded[64] = {0}; // 512-bit buffer
    
    // Simple padding: place message at the end
    if (msg_len <= 64) {
        memcpy(padded + (64 - msg_len), msg, msg_len);
    }

    // Set the early-exit limit in the library
    mbedtls_mpi_stop_bits = stop_bits;

    for (uint32_t i = 0; i < iterations; i++) {
        // This will now stop after 'stop_bits' bits because of your library surgery
        mbedtls_rsa_public(&global_rsa, padded, sig);
    }
    
    return 0;
}