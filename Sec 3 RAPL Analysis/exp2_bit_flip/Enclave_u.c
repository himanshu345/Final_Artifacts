#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_setup_key_t {
	int ms_retval;
	const unsigned char* ms_n;
	size_t ms_n_len;
	const unsigned char* ms_d;
	size_t ms_d_len;
} ms_ecall_setup_key_t;

typedef struct ms_ecall_rsa_benchmark_t {
	int ms_retval;
	const unsigned char* ms_msg;
	size_t ms_msg_len;
	unsigned char* ms_sig;
	size_t ms_sig_len;
	uint32_t ms_iterations;
} ms_ecall_rsa_benchmark_t;

typedef struct ms_ocall_mbedtls_net_connect_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const char* ms_host;
	const char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_connect_t;

typedef struct ms_ocall_mbedtls_net_bind_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const char* ms_bind_ip;
	const char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_bind_t;

typedef struct ms_ocall_mbedtls_net_accept_t {
	int ms_retval;
	mbedtls_net_context* ms_bind_ctx;
	mbedtls_net_context* ms_client_ctx;
	void* ms_client_ip;
	size_t ms_buf_size;
	size_t* ms_ip_len;
} ms_ocall_mbedtls_net_accept_t;

typedef struct ms_ocall_mbedtls_net_set_block_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_block_t;

typedef struct ms_ocall_mbedtls_net_set_nonblock_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_nonblock_t;

typedef struct ms_ocall_mbedtls_net_usleep_t {
	unsigned long int ms_usec;
} ms_ocall_mbedtls_net_usleep_t;

typedef struct ms_ocall_mbedtls_net_recv_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_recv_t;

typedef struct ms_ocall_mbedtls_net_send_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_send_t;

typedef struct ms_ocall_mbedtls_net_recv_timeout_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
	uint32_t ms_timeout;
} ms_ocall_mbedtls_net_recv_timeout_t;

typedef struct ms_ocall_mbedtls_net_free_t {
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_free_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_connect(void* pms)
{
	ms_ocall_mbedtls_net_connect_t* ms = SGX_CAST(ms_ocall_mbedtls_net_connect_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_connect(ms->ms_ctx, ms->ms_host, ms->ms_port, ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_bind(void* pms)
{
	ms_ocall_mbedtls_net_bind_t* ms = SGX_CAST(ms_ocall_mbedtls_net_bind_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_bind(ms->ms_ctx, ms->ms_bind_ip, ms->ms_port, ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_accept(void* pms)
{
	ms_ocall_mbedtls_net_accept_t* ms = SGX_CAST(ms_ocall_mbedtls_net_accept_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_accept(ms->ms_bind_ctx, ms->ms_client_ctx, ms->ms_client_ip, ms->ms_buf_size, ms->ms_ip_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_set_block(void* pms)
{
	ms_ocall_mbedtls_net_set_block_t* ms = SGX_CAST(ms_ocall_mbedtls_net_set_block_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_set_block(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_set_nonblock(void* pms)
{
	ms_ocall_mbedtls_net_set_nonblock_t* ms = SGX_CAST(ms_ocall_mbedtls_net_set_nonblock_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_set_nonblock(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_usleep(void* pms)
{
	ms_ocall_mbedtls_net_usleep_t* ms = SGX_CAST(ms_ocall_mbedtls_net_usleep_t*, pms);
	ocall_mbedtls_net_usleep(ms->ms_usec);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_recv(void* pms)
{
	ms_ocall_mbedtls_net_recv_t* ms = SGX_CAST(ms_ocall_mbedtls_net_recv_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_recv(ms->ms_ctx, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_send(void* pms)
{
	ms_ocall_mbedtls_net_send_t* ms = SGX_CAST(ms_ocall_mbedtls_net_send_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_send(ms->ms_ctx, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_recv_timeout(void* pms)
{
	ms_ocall_mbedtls_net_recv_timeout_t* ms = SGX_CAST(ms_ocall_mbedtls_net_recv_timeout_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_recv_timeout(ms->ms_ctx, ms->ms_buf, ms->ms_len, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_free(void* pms)
{
	ms_ocall_mbedtls_net_free_t* ms = SGX_CAST(ms_ocall_mbedtls_net_free_t*, pms);
	ocall_mbedtls_net_free(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ms->ms_retval = ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[11];
} ocall_table_Enclave = {
	11,
	{
		(void*)Enclave_ocall_mbedtls_net_connect,
		(void*)Enclave_ocall_mbedtls_net_bind,
		(void*)Enclave_ocall_mbedtls_net_accept,
		(void*)Enclave_ocall_mbedtls_net_set_block,
		(void*)Enclave_ocall_mbedtls_net_set_nonblock,
		(void*)Enclave_ocall_mbedtls_net_usleep,
		(void*)Enclave_ocall_mbedtls_net_recv,
		(void*)Enclave_ocall_mbedtls_net_send,
		(void*)Enclave_ocall_mbedtls_net_recv_timeout,
		(void*)Enclave_ocall_mbedtls_net_free,
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t ecall_setup_key(sgx_enclave_id_t eid, int* retval, const unsigned char* n, size_t n_len, const unsigned char* d, size_t d_len)
{
	sgx_status_t status;
	ms_ecall_setup_key_t ms;
	ms.ms_n = n;
	ms.ms_n_len = n_len;
	ms.ms_d = d;
	ms.ms_d_len = d_len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_rsa_benchmark(sgx_enclave_id_t eid, int* retval, const unsigned char* msg, size_t msg_len, unsigned char* sig, size_t sig_len, uint32_t iterations)
{
	sgx_status_t status;
	ms_ecall_rsa_benchmark_t ms;
	ms.ms_msg = msg;
	ms.ms_msg_len = msg_len;
	ms.ms_sig = sig;
	ms.ms_sig_len = sig_len;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

