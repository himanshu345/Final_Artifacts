#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_setup_key_t {
	int ms_retval;
	const unsigned char* ms_n;
	size_t ms_n_len;
	const unsigned char* ms_d;
	size_t ms_d_len;
} ms_ecall_setup_key_t;

typedef struct ms_ecall_empty_loop_t {
	uint32_t ms_iterations;
} ms_ecall_empty_loop_t;

typedef struct ms_ecall_rsa_partial_benchmark_t {
	int ms_retval;
	const unsigned char* ms_msg;
	size_t ms_msg_len;
	unsigned char* ms_sig;
	size_t ms_sig_len;
	int ms_stop_bits;
	uint32_t ms_iterations;
} ms_ecall_rsa_partial_benchmark_t;

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

static sgx_status_t SGX_CDECL sgx_ecall_setup_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_setup_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_setup_key_t* ms = SGX_CAST(ms_ecall_setup_key_t*, pms);
	ms_ecall_setup_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_setup_key_t), ms, sizeof(ms_ecall_setup_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_n = __in_ms.ms_n;
	size_t _tmp_n_len = __in_ms.ms_n_len;
	size_t _len_n = _tmp_n_len;
	unsigned char* _in_n = NULL;
	const unsigned char* _tmp_d = __in_ms.ms_d;
	size_t _tmp_d_len = __in_ms.ms_d_len;
	size_t _len_d = _tmp_d_len;
	unsigned char* _in_d = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_n, _len_n);
	CHECK_UNIQUE_POINTER(_tmp_d, _len_d);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_n != NULL && _len_n != 0) {
		if ( _len_n % sizeof(*_tmp_n) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_n = (unsigned char*)malloc(_len_n);
		if (_in_n == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_n, _len_n, _tmp_n, _len_n)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_d != NULL && _len_d != 0) {
		if ( _len_d % sizeof(*_tmp_d) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_d = (unsigned char*)malloc(_len_d);
		if (_in_d == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_d, _len_d, _tmp_d, _len_d)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_setup_key((const unsigned char*)_in_n, _tmp_n_len, (const unsigned char*)_in_d, _tmp_d_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_n) free(_in_n);
	if (_in_d) free(_in_d);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_empty_loop(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_empty_loop_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_empty_loop_t* ms = SGX_CAST(ms_ecall_empty_loop_t*, pms);
	ms_ecall_empty_loop_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_empty_loop_t), ms, sizeof(ms_ecall_empty_loop_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_empty_loop(__in_ms.ms_iterations);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_rsa_partial_benchmark(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_rsa_partial_benchmark_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_rsa_partial_benchmark_t* ms = SGX_CAST(ms_ecall_rsa_partial_benchmark_t*, pms);
	ms_ecall_rsa_partial_benchmark_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_rsa_partial_benchmark_t), ms, sizeof(ms_ecall_rsa_partial_benchmark_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_msg = __in_ms.ms_msg;
	size_t _tmp_msg_len = __in_ms.ms_msg_len;
	size_t _len_msg = _tmp_msg_len;
	unsigned char* _in_msg = NULL;
	unsigned char* _tmp_sig = __in_ms.ms_sig;
	size_t _tmp_sig_len = __in_ms.ms_sig_len;
	size_t _len_sig = _tmp_sig_len;
	unsigned char* _in_sig = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_msg, _len_msg);
	CHECK_UNIQUE_POINTER(_tmp_sig, _len_sig);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg != NULL && _len_msg != 0) {
		if ( _len_msg % sizeof(*_tmp_msg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_msg = (unsigned char*)malloc(_len_msg);
		if (_in_msg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg, _len_msg, _tmp_msg, _len_msg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sig != NULL && _len_sig != 0) {
		if ( _len_sig % sizeof(*_tmp_sig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sig = (unsigned char*)malloc(_len_sig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sig, 0, _len_sig);
	}
	_in_retval = ecall_rsa_partial_benchmark((const unsigned char*)_in_msg, _tmp_msg_len, _in_sig, _tmp_sig_len, __in_ms.ms_stop_bits, __in_ms.ms_iterations);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sig) {
		if (memcpy_verw_s(_tmp_sig, _len_sig, _in_sig, _len_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg) free(_in_msg);
	if (_in_sig) free(_in_sig);
	return status;
}

static sgx_status_t SGX_CDECL sgx_dummy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	dummy();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_setup_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_empty_loop, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_rsa_partial_benchmark, 0, 0},
		{(void*)(uintptr_t)sgx_dummy, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[11][4];
} g_dyn_entry_table = {
	11,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_mbedtls_net_connect(int* retval, mbedtls_net_context* ctx, const char* host, const char* port, int proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_host = host ? strlen(host) + 1 : 0;
	size_t _len_port = port ? strlen(port) + 1 : 0;

	ms_ocall_mbedtls_net_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_connect_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(host, _len_host);
	CHECK_ENCLAVE_POINTER(port, _len_port);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (host != NULL) ? _len_host : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (port != NULL) ? _len_port : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_connect_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_connect_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	if (host != NULL) {
		if (memcpy_verw_s(&ms->ms_host, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_host % sizeof(*host) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, host, _len_host)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_host);
		ocalloc_size -= _len_host;
	} else {
		ms->ms_host = NULL;
	}

	if (port != NULL) {
		if (memcpy_verw_s(&ms->ms_port, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_port % sizeof(*port) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, port, _len_port)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_port);
		ocalloc_size -= _len_port;
	} else {
		ms->ms_port = NULL;
	}

	if (memcpy_verw_s(&ms->ms_proto, sizeof(ms->ms_proto), &proto, sizeof(proto))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_bind(int* retval, mbedtls_net_context* ctx, const char* bind_ip, const char* port, int proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_bind_ip = bind_ip ? strlen(bind_ip) + 1 : 0;
	size_t _len_port = port ? strlen(port) + 1 : 0;

	ms_ocall_mbedtls_net_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_bind_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(bind_ip, _len_bind_ip);
	CHECK_ENCLAVE_POINTER(port, _len_port);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bind_ip != NULL) ? _len_bind_ip : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (port != NULL) ? _len_port : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_bind_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_bind_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		memset_verw(__tmp_ctx, 0, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	if (bind_ip != NULL) {
		if (memcpy_verw_s(&ms->ms_bind_ip, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_bind_ip % sizeof(*bind_ip) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, bind_ip, _len_bind_ip)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bind_ip);
		ocalloc_size -= _len_bind_ip;
	} else {
		ms->ms_bind_ip = NULL;
	}

	if (port != NULL) {
		if (memcpy_verw_s(&ms->ms_port, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_port % sizeof(*port) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, port, _len_port)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_port);
		ocalloc_size -= _len_port;
	} else {
		ms->ms_port = NULL;
	}

	if (memcpy_verw_s(&ms->ms_proto, sizeof(ms->ms_proto), &proto, sizeof(proto))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_accept(int* retval, mbedtls_net_context* bind_ctx, mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size, size_t* ip_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_bind_ctx = sizeof(mbedtls_net_context);
	size_t _len_client_ctx = sizeof(mbedtls_net_context);
	size_t _len_client_ip = buf_size;
	size_t _len_ip_len = sizeof(size_t);

	ms_ocall_mbedtls_net_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_accept_t);
	void *__tmp = NULL;

	void *__tmp_client_ctx = NULL;
	void *__tmp_client_ip = NULL;
	void *__tmp_ip_len = NULL;

	CHECK_ENCLAVE_POINTER(bind_ctx, _len_bind_ctx);
	CHECK_ENCLAVE_POINTER(client_ctx, _len_client_ctx);
	CHECK_ENCLAVE_POINTER(client_ip, _len_client_ip);
	CHECK_ENCLAVE_POINTER(ip_len, _len_ip_len);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bind_ctx != NULL) ? _len_bind_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (client_ctx != NULL) ? _len_client_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (client_ip != NULL) ? _len_client_ip : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ip_len != NULL) ? _len_ip_len : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_accept_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_accept_t);

	if (bind_ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_bind_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, bind_ctx, _len_bind_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bind_ctx);
		ocalloc_size -= _len_bind_ctx;
	} else {
		ms->ms_bind_ctx = NULL;
	}

	if (client_ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_client_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_client_ctx = __tmp;
		memset_verw(__tmp_client_ctx, 0, _len_client_ctx);
		__tmp = (void *)((size_t)__tmp + _len_client_ctx);
		ocalloc_size -= _len_client_ctx;
	} else {
		ms->ms_client_ctx = NULL;
	}

	if (client_ip != NULL) {
		if (memcpy_verw_s(&ms->ms_client_ip, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_client_ip = __tmp;
		memset_verw(__tmp_client_ip, 0, _len_client_ip);
		__tmp = (void *)((size_t)__tmp + _len_client_ip);
		ocalloc_size -= _len_client_ip;
	} else {
		ms->ms_client_ip = NULL;
	}

	if (memcpy_verw_s(&ms->ms_buf_size, sizeof(ms->ms_buf_size), &buf_size, sizeof(buf_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (ip_len != NULL) {
		if (memcpy_verw_s(&ms->ms_ip_len, sizeof(size_t*), &__tmp, sizeof(size_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ip_len = __tmp;
		if (_len_ip_len % sizeof(*ip_len) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_ip_len, 0, _len_ip_len);
		__tmp = (void *)((size_t)__tmp + _len_ip_len);
		ocalloc_size -= _len_ip_len;
	} else {
		ms->ms_ip_len = NULL;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (client_ctx) {
			if (memcpy_s((void*)client_ctx, _len_client_ctx, __tmp_client_ctx, _len_client_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (client_ip) {
			if (memcpy_s((void*)client_ip, _len_client_ip, __tmp_client_ip, _len_client_ip)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ip_len) {
			if (memcpy_s((void*)ip_len, _len_ip_len, __tmp_ip_len, _len_ip_len)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_set_block(int* retval, mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);

	ms_ocall_mbedtls_net_set_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_set_block_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_set_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_set_block_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_set_block_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_set_nonblock(int* retval, mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);

	ms_ocall_mbedtls_net_set_nonblock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_set_nonblock_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_set_nonblock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_set_nonblock_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_set_nonblock_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_usleep(unsigned long int usec)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mbedtls_net_usleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_usleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_usleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_usleep_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_usleep_t);

	if (memcpy_verw_s(&ms->ms_usec, sizeof(ms->ms_usec), &usec, sizeof(usec))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_recv(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_recv_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_recv_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_recv_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(unsigned char*), &__tmp, sizeof(unsigned char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_send(int* retval, mbedtls_net_context* ctx, const unsigned char* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_send_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_send_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_send_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const unsigned char*), &__tmp, sizeof(const unsigned char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_recv_timeout(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_recv_timeout_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_recv_timeout_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_recv_timeout_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_recv_timeout_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_recv_timeout_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(unsigned char*), &__tmp, sizeof(unsigned char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_free(mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);

	ms_ocall_mbedtls_net_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_free_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_free_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_free_t);

	if (ctx != NULL) {
		if (memcpy_verw_s(&ms->ms_ctx, sizeof(mbedtls_net_context*), &__tmp, sizeof(mbedtls_net_context*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ctx = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

