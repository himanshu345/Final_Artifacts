#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "mbedtls/net.h"
#include "mbedtls/timing.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_MBEDTLS_NET_CONNECT_DEFINED__
#define OCALL_MBEDTLS_NET_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_connect, (mbedtls_net_context* ctx, const char* host, const char* port, int proto));
#endif
#ifndef OCALL_MBEDTLS_NET_BIND_DEFINED__
#define OCALL_MBEDTLS_NET_BIND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_bind, (mbedtls_net_context* ctx, const char* bind_ip, const char* port, int proto));
#endif
#ifndef OCALL_MBEDTLS_NET_ACCEPT_DEFINED__
#define OCALL_MBEDTLS_NET_ACCEPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_accept, (mbedtls_net_context* bind_ctx, mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size, size_t* ip_len));
#endif
#ifndef OCALL_MBEDTLS_NET_SET_BLOCK_DEFINED__
#define OCALL_MBEDTLS_NET_SET_BLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_set_block, (mbedtls_net_context* ctx));
#endif
#ifndef OCALL_MBEDTLS_NET_SET_NONBLOCK_DEFINED__
#define OCALL_MBEDTLS_NET_SET_NONBLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_set_nonblock, (mbedtls_net_context* ctx));
#endif
#ifndef OCALL_MBEDTLS_NET_USLEEP_DEFINED__
#define OCALL_MBEDTLS_NET_USLEEP_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_usleep, (unsigned long int usec));
#endif
#ifndef OCALL_MBEDTLS_NET_RECV_DEFINED__
#define OCALL_MBEDTLS_NET_RECV_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_recv, (mbedtls_net_context* ctx, unsigned char* buf, size_t len));
#endif
#ifndef OCALL_MBEDTLS_NET_SEND_DEFINED__
#define OCALL_MBEDTLS_NET_SEND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_send, (mbedtls_net_context* ctx, const unsigned char* buf, size_t len));
#endif
#ifndef OCALL_MBEDTLS_NET_RECV_TIMEOUT_DEFINED__
#define OCALL_MBEDTLS_NET_RECV_TIMEOUT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_recv_timeout, (mbedtls_net_context* ctx, unsigned char* buf, size_t len, uint32_t timeout));
#endif
#ifndef OCALL_MBEDTLS_NET_FREE_DEFINED__
#define OCALL_MBEDTLS_NET_FREE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_free, (mbedtls_net_context* ctx));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t ecall_setup_key(sgx_enclave_id_t eid, int* retval, const unsigned char* n, size_t n_len, const unsigned char* d, size_t d_len);
sgx_status_t ecall_empty_loop(sgx_enclave_id_t eid, uint32_t iterations);
sgx_status_t ecall_rsa_partial_benchmark(sgx_enclave_id_t eid, int* retval, const unsigned char* msg, size_t msg_len, unsigned char* sig, size_t sig_len, int stop_bits, uint32_t iterations);
sgx_status_t dummy(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
