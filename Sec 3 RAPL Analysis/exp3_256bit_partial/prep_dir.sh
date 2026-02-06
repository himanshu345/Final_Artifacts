#!/bin/bash

# Define the library directory
LIB_DIR="./mbedtls_SGX-2.6.0"

if [ ! -d "$LIB_DIR" ]; then
    echo "Error: $LIB_DIR not found!"
    echo "Please ensure you have built the library and copied the mbedtls_SGX-2.6.0 folder here."
    exit 1
fi

echo "Creating Enclave.edl..."
cat << 'EOF' > Enclave.edl
enclave {
    from "mbedtls_sgx.edl" import *;

    trusted {
        public void ecall_rsa_sign(
            [in, size=msg_len] const unsigned char* msg, 
            size_t msg_len, 
            [out, size=sig_len] unsigned char* sig, 
            size_t sig_len
        );
    };
};
EOF

echo "Creating Enclave.config.xml..."
cat << 'EOF' > Enclave.config.xml
<EnclaveConfiguration>
  <StackMaxSize>0x40000</StackMaxSize>
  <HeapMaxSize>0x100000</HeapMaxSize>
  <TCSNum>1</TCSNum>
  <TCSPolicy>1</TCSPolicy>
  <DisableDebug>0</DisableDebug>
  <MiscSelect>0</MiscSelect>
  <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
EOF

echo "Creating Enclave.c..."
cat << 'EOF' > Enclave.c
#include "Enclave_t.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include <string.h>

void ecall_rsa_sign(const unsigned char* msg, size_t msg_len, unsigned char* sig, size_t sig_len) {
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_gen_key";
    unsigned char hash[32]; 

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    // Seed RNG
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

    // Generate 2048-bit RSA Key
    mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);

    // Hash the message (SHA-256)
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg, msg_len, hash);

    // Sign the hash
    mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 32, hash, sig);

    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}
EOF

echo "Creating App.cpp..."
cat << 'EOF' > App.cpp
#include <iostream>
#include <cstdio>
#include <cstring>
#include "sgx_urts.h"
#include "Enclave_u.h"

int main() {
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave, error code: 0x%x\n", ret);
        return 1;
    }

    const char* message = "Hello from the untrusted world!";
    unsigned char signature[256] = {0}; 

    printf("Enclave created. Calling RSA sign...\n");

    ecall_rsa_sign(eid, (const unsigned char*)message, strlen(message), signature, 256);

    printf("RSA Signing Successful!\nSignature (first 16 bytes): ");
    for(int i=0; i<16; i++) printf("%02x ", signature[i]);
    printf("...\n");

    sgx_destroy_enclave(eid);
    return 0;
}
EOF

echo "Creating Makefile..."
cat << 'EOF' > Makefile
SGX_SDK ?= /opt/intel/sgxsdk
MBEDTLS_SGX_DIR = ./mbedtls_SGX-2.6.0

App_C_Flags := -fPIC -Wno-attributes -I$(SGX_SDK)/include -I$(MBEDTLS_SGX_DIR)/include
Enclave_C_Flags := -static -nosimd -nostdinc -fvisibility=hidden -fpie -fstack-protector \
                   -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(MBEDTLS_SGX_DIR)/include

App_Link_Flags := -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread -L$(MBEDTLS_SGX_DIR)/lib -lmbedtls_sgx_u
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 \
    -Wl,--start-group -L$(MBEDTLS_SGX_DIR)/lib -lmbedtls_sgx_t -lsgx_tstdc -lsgx_tcxx -lsgx_tservice -lsgx_tcrypto -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0

all: enclave.signed.so app

App_u.c: Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --untrusted Enclave.edl --search-path $(MBEDTLS_SGX_DIR)/lib --search-path $(SGX_SDK)/include

app: App_u.c App.cpp
	g++ $(App_C_Flags) $^ -o $@ $(App_Link_Flags)

Enclave_t.c: Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --trusted Enclave.edl --search-path $(MBEDTLS_SGX_DIR)/lib --search-path $(SGX_SDK)/include

enclave.so: Enclave_t.c Enclave.c
	gcc $(Enclave_C_Flags) -c Enclave_t.c -o Enclave_t.o
	gcc $(Enclave_C_Flags) -c Enclave.c -o Enclave.o
	g++ Enclave_t.o Enclave.o -o $@ $(Enclave_Link_Flags)

enclave.signed.so: enclave.so
	$(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave_private.pem -enclave enclave.so -out $@ -config Enclave.config.xml || \
	(openssl genrsa -out Enclave_private.pem 3072 && $(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave_private.pem -enclave enclave.so -out $@ -config Enclave.config.xml)

clean:
	rm -f app enclave.so enclave.signed.so Enclave_t.* Enclave_u.* *.o Enclave_private.pem
EOF

chmod +x prep_dir.sh
echo "Done! Run ./prep_dir.sh then 'make' and './app'"