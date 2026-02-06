#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <chrono>
#include <vector>
#include <cstring>
#include "sgx_urts.h"
#include "Enclave_u.h"

#define MSR_RAPL_POWER_UNIT    0x606
#define MSR_PP0_ENERGY_STATUS  0x639 
#define ITERATIONS 5000

struct TestResult {
    double total_energy;
    double total_time;
    uint32_t iters;
    unsigned char last_sig[256];
};

uint64_t read_msr(int cpu, uint32_t reg) {
    char path[32];
    sprintf(path, "/dev/cpu/%d/msr", cpu);
    int fd = open(path, O_RDONLY);
    uint64_t data = 0;
    pread(fd, &data, sizeof(data), reg);
    close(fd);
    return data;
}

double get_energy_unit() {
    uint64_t unit_raw = read_msr(0, MSR_RAPL_POWER_UNIT);
    return 1.0 / pow(2, (unit_raw >> 8) & 0x1F);
}

void print_signature(const unsigned char* sig) {
    printf("Last Signature (first 16 bytes): ");
    for(int i = 0; i < 16; i++) printf("%02x ", sig[i]);
    printf("... ");
    for(int i = 240; i < 256; i++) printf("%02x ", sig[i]);
    printf("\n");
}

void print_phase_report(const char* label, TestResult r) {
    double avg_energy_uj = (r.total_energy * 1000000.0) / r.iters;
    double avg_power_w = r.total_energy / r.total_time;
    double throughput = r.iters / r.total_time;

    printf("\n--- PHASE: %s ---\n", label);
    printf("Total Iterations:    %u\n", r.iters);
    printf("Total Time:          %.4f seconds\n", r.total_time);
    printf("Total Energy used:   %.6f Joules\n", r.total_energy);
    printf("Avg Energy per Sign: %.4f uJ\n", avg_energy_uj);
    printf("Average Power Draw:  %.4f Watts\n", avg_power_w);
    printf("Throughput:          %.2f signs/second\n", throughput);
    if (r.iters > 0 && r.last_sig[0] != 0) print_signature(r.last_sig);
}

TestResult run_benchmark(sgx_enclave_id_t eid, int mode, uint32_t iterations, const unsigned char* msg) {
    double unit = get_energy_unit();
    TestResult result = {0, 0, iterations, {0}};
    int enclave_ret = 0;

    uint64_t start_tick = read_msr(0, MSR_PP0_ENERGY_STATUS);
    auto start_time = std::chrono::high_resolution_clock::now();

    if (mode == 0) {
        ecall_empty_loop(eid, iterations);
    } else {
        ecall_rsa_sign_benchmark(eid, &enclave_ret, msg, 32, result.last_sig, 256, iterations);
        if (enclave_ret != 0) printf("[!] Enclave Sign Error: -0x%x\n", -enclave_ret);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    uint64_t end_tick = read_msr(0, MSR_PP0_ENERGY_STATUS);

    std::chrono::duration<double> diff = end_time - start_time;
    result.total_energy = (double)(end_tick - start_tick) * unit;
    result.total_time = diff.count();
    return result;
}

int main() {
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    if (sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &eid, NULL) != SGX_SUCCESS) return 1;

    int enclave_ret;
    printf("[+] Provisioning RSA key (Non-CRT Mode)...\n");
    ecall_setup_key(eid, &enclave_ret);
    
    // Non-CRT is slow, 1000 is a good starting point for measurement
    uint32_t iters = ITERATIONS; 
    unsigned char msg_zeros[32]; memset(msg_zeros, 0x00, 32);
    unsigned char msg_ones[32];  memset(msg_ones, 0xFF, 32);

    TestResult res_base = run_benchmark(eid, 0, iters, NULL);
    print_phase_report("BASELINE", res_base);

    TestResult res_zeros = run_benchmark(eid, 1, iters, msg_zeros);
    print_phase_report("RSA SIGN (0x00)", res_zeros);

    TestResult res_ones = run_benchmark(eid, 1, iters, msg_ones);
    print_phase_report("RSA SIGN (0xFF)", res_ones);

    double pure_zeros_uj = ((res_zeros.total_energy - res_base.total_energy) * 1e6) / iters;
    double pure_ones_uj = ((res_ones.total_energy - res_base.total_energy) * 1e6) / iters;
    double delta_uj = pure_ones_uj - pure_zeros_uj;

    printf("\n================= DIFFERENTIAL SUMMARY =================\n");
    printf("Pure RSA Energy (Zeros): %.4f uJ/sign\n", pure_zeros_uj);
    printf("Pure RSA Energy (Ones):  %.4f uJ/sign\n", pure_ones_uj);
    printf("Leakage Delta:           %.4f uJ/sign\n", delta_uj);
    printf("Leakage Percentage:      %.4f %%\n", (delta_uj / pure_zeros_uj) * 100.0);
    printf("========================================================\n");

    sgx_destroy_enclave(eid);
    return 0;
}