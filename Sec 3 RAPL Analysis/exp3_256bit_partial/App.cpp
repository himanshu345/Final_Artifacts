#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <chrono>
#include <vector>
#include <cstring>
#include <sys/stat.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "key.h" // Contains the 512-bit rsa_n and rsa_d

#define MSR_RAPL_POWER_UNIT    0x606
#define MSR_PP0_ENERGY_STATUS  0x639 

// RESEARCH PARAMETERS
#define ITERATIONS 1000    // 512-bit is fast, need high iters for RAPL
#define NUM_MESSAGES 1200000     // Number of random points for correlation
#define STOP_BITS 15          // Stop after 3 windows (3 bits each)

uint64_t read_msr(uint32_t reg) {
    int fd = open("/dev/cpu/0/msr", O_RDONLY);
    uint64_t data = 0;
    pread(fd, &data, sizeof(data), reg);
    close(fd);
    return data;
}

double get_energy_unit() {
    uint64_t unit_raw = read_msr(MSR_RAPL_POWER_UNIT);
    return 1.0 / pow(2, (unit_raw >> 8) & 0x1F);
}

int main() {
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    if (sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) {
        printf("Failed to create enclave.\n");
        return 1;
    }

    int enclave_ret;
    printf("[+] Provisioning 512-bit RSA key (Non-CRT)...\n");
    ecall_setup_key(eid, &enclave_ret, rsa_n, rsa_n_len, rsa_d, rsa_d_len);
    if (enclave_ret != 0) {
        printf("Setup failed!\n");
        return 1;
    }

    // Create data directory for logging
    std::string dir = "data/exp3_" + std::to_string(std::time(nullptr));
    mkdir("data", 0777); mkdir(dir.c_str(), 0777);
    std::ofstream log(dir + "/correlation.csv");
    log << "msg_id,msg_hex,energy_uj,time_s\n";

    double unit = get_energy_unit();
    printf("[+] Starting Correlation Sweep (%d messages, stop_bits=%d)\n", NUM_MESSAGES, STOP_BITS);

    for (int m = 0; m < NUM_MESSAGES; m++) {
        unsigned char rand_msg[32];
        char msg_hex[65] = {0};
        for(int i=0; i<32; i++) {
            rand_msg[i] = rand() % 256;
            sprintf(msg_hex + (i*2), "%02x", rand_msg[i]);
        }

        printf("Msg %d/%d... ", m+1, NUM_MESSAGES);
        fflush(stdout);

        // BUFFER FIX: We need a 64-byte buffer for the 512-bit partial result
        unsigned char sig[64] = {0}; 
        
        uint64_t e1 = read_msr(MSR_PP0_ENERGY_STATUS);
        auto t1 = std::chrono::high_resolution_clock::now();

        // ARGUMENT FIX: Added 'sig' and '64' to the call
        ecall_rsa_partial_benchmark(eid, &enclave_ret, rand_msg, 32, sig, 64, STOP_BITS, ITERATIONS);

        auto t2 = std::chrono::high_resolution_clock::now();
        uint64_t e2 = read_msr(MSR_PP0_ENERGY_STATUS);

        std::chrono::duration<double> diff = t2 - t1;
        double energy_uj = (double)(e2 - e1) * unit * 1e6 / ITERATIONS;

        log << m << "," << msg_hex << "," << energy_uj << "," << diff.count() << "\n";
        printf("Energy: %.4f uJ/sign\n", energy_uj);
    }

    printf("\n[+] Data saved to %s/correlation.csv\n", dir.c_str());
    sgx_destroy_enclave(eid);
    return 0;
}