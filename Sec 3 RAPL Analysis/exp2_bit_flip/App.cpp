#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <chrono>
#include <vector>
#include <numeric>
#include <sys/stat.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "keys.h"

#define MSR_RAPL_POWER_UNIT    0x606
#define MSR_PP0_ENERGY_STATUS  0x639 

const int SAMPLES_PER_KEY = 500;  // Reduced slightly for speed, but still statistically significant
const int SIGNS_PER_SAMPLE = 100;

uint64_t read_msr(uint32_t reg) {
    int fd = open("/dev/cpu/0/msr", O_RDONLY);
    uint64_t data;
    pread(fd, &data, sizeof(data), reg);
    close(fd);
    return data;
}

struct Stats { double mean; double std_dev; };

Stats calculate_stats(const std::vector<double>& data) {
    double sum = std::accumulate(data.begin(), data.end(), 0.0);
    double mean = sum / data.size();
    double sq_sum = std::inner_product(data.begin(), data.end(), data.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / data.size() - mean * mean);
    return {mean, stdev};
}

int main() {
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

    std::string timestamp = std::to_string(std::time(nullptr));
    std::string dir = "data/exp2_bitflip_" + timestamp;
    mkdir("data", 0777); mkdir(dir.c_str(), 0777);

    std::ofstream summary(dir + "/summary.csv");
    summary << "label,bit_pos,mean_uj,stddev_uj\n";

    double unit = 1.0 / pow(2, (read_msr(MSR_RAPL_POWER_UNIT) >> 8) & 0x1F);
    unsigned char msg[32] = {0x42};
    unsigned char sig[384];

    printf("[+] Exp 2: Single Bit Flip Sensitivity\n");

    for (int k = 0; k < 16; k++) {
        printf("Testing %s... ", exp_keys[k].label);
        fflush(stdout);

        std::vector<double> sample_energies;
        std::ofstream raw(dir + "/" + std::string(exp_keys[k].label) + "_raw.csv");
        raw << "sample_id,energy_uj\n";

        ecall_setup_key(eid, &updated, rsa_n, rsa_n_len, exp_keys[k].data, exp_keys[k].len);

        for (int s = 0; s < SAMPLES_PER_KEY; s++) {
            uint64_t e1 = read_msr(MSR_PP0_ENERGY_STATUS);
            ecall_rsa_benchmark(eid, &updated, msg, 32, sig, 384, SIGNS_PER_SAMPLE);
            uint64_t e2 = read_msr(MSR_PP0_ENERGY_STATUS);

            double energy = (double)(e2 - e1) * unit * 1e6 / SIGNS_PER_SAMPLE;
            sample_energies.push_back(energy);
            raw << s << "," << energy << "\n";
        }

        Stats s = calculate_stats(sample_energies);
        summary << exp_keys[k].label << "," << exp_keys[k].bit_flipped << "," << s.mean << "," << s.std_dev << "\n";
        printf("Mean: %.2f uJ\n", s.mean);
    }

    sgx_destroy_enclave(eid);
    return 0;
}