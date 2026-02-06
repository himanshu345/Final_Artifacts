SGX_SDK ?= /opt/intel/sgxsdk
MBEDTLS_SGX_DIR = /home/agv/sgx-research/mbedtls-SGX-exp3/build/mbedtls_SGX-2.6.0

# Paths
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

# Flags for App
App_C_Flags := -fPIC -Wno-attributes -I$(SGX_SDK)/include -I$(MBEDTLS_SGX_DIR)/include
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts -lpthread -L$(MBEDTLS_SGX_DIR)/lib -lmbedtls_SGX_u

# Flags for Enclave
Enclave_C_Flags := -static -nostdinc -fvisibility=hidden -fPIC -fstack-protector \
                   -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(MBEDTLS_SGX_DIR)/include

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
    -Wl,--start-group -L$(MBEDTLS_SGX_DIR)/lib -lmbedtls_SGX_t -lsgx_tstdc -lsgx_tcxx -lsgx_tservice -lsgx_tcrypto -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-shared,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0

all: enclave.signed.so app

# Build App
Enclave_u.c: Enclave.edl
	$(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(MBEDTLS_SGX_DIR)/lib --search-path $(SGX_SDK)/include

app: Enclave_u.c App.cpp
	g++ $(App_C_Flags) $^ -o $@ $(App_Link_Flags)

# Build Enclave
Enclave_t.c: Enclave.edl
	$(SGX_EDGER8R) --trusted Enclave.edl --search-path $(MBEDTLS_SGX_DIR)/lib --search-path $(SGX_SDK)/include

Enclave_t.o: Enclave_t.c
	gcc $(Enclave_C_Flags) -c $< -o $@

Enclave.o: Enclave.c
	gcc $(Enclave_C_Flags) -c $< -o $@

enclave.so: Enclave_t.o Enclave.o
	g++ $^ -o $@ $(Enclave_Link_Flags)

enclave.signed.so: enclave.so
	$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave enclave.so -out $@ -config Enclave.config.xml || \
	(openssl genrsa -3 -out Enclave_private.pem 3072 && $(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave enclave.so -out $@ -config Enclave.config.xml)

clean:
	rm -f app enclave.so enclave.signed.so Enclave_t.* Enclave_u.* *.o Enclave_private.pem