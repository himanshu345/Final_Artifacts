#include "Enclave_t.h"
#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"
#include <string.h>

static mbedtls_rsa_context global_rsa;
static int is_init = 0;

int ecall_setup_key(const unsigned char* n, size_t n_len, const unsigned char* d, size_t d_len) {
    if (is_init) mbedtls_rsa_free(&global_rsa);
    mbedtls_rsa_init(&global_rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_mpi_read_binary(&global_rsa.N, n, n_len);
    mbedtls_mpi_read_binary(&global_rsa.E, d, d_len); // Public Hack
    global_rsa.len = mbedtls_mpi_size(&global_rsa.N);
    is_init = 1;
    return 0;
}

int ecall_rsa_benchmark(const unsigned char* msg, size_t msg_len, unsigned char* sig, size_t sig_len, uint32_t iterations) {
    unsigned char padded[384] = {0};
    memcpy(padded + (384 - msg_len), msg, msg_len);
    for (uint32_t i = 0; i < iterations; i++) {
        mbedtls_rsa_public(&global_rsa, padded, sig);
    }
    return 0;
}