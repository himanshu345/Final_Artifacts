#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <vector>
#include <cstdlib>
#include <cmath>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

#define RAPL_Package "/sys/devices/virtual/powercap/intel-rapl/intel-rapl:0/intel-rapl:0:0/energy_uj"

using namespace std;
using namespace std::chrono;

// Launch Chrome in a new process group
pid_t launch_chrome(const std::string& command) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: start new process group
        setpgid(0, 0);
        execl("/bin/sh", "sh", "-c", command.c_str(), (char*) nullptr);
        exit(1); // if execl fails
    }
    return pid; // Parent: returns child's PID
}

// Read RAPL energy
long read_rapl(const char* filename) {
    ifstream file(filename);
    long energy = 0;
    if (file.is_open()) {
        file >> energy;
        file.close();
    } else {
        cerr << "Failed to read RAPL file: " << filename << endl;
    }
    return energy;
}

// Measure power consumption
void measure_power(const string& website, const string& url) {
    cout << "Opening website: " << website << endl;

    int num_traces = 10000;
    int num_samples = 1000;
    vector<vector<long>> traces(num_traces, vector<long>(num_samples, 0)); // traces[trace][sample]

    for (int trace = 0; trace < num_traces; ++trace) {
        std::string user_profile = "/tmp/guest-profile-" + std::to_string(trace);
        std::string chrome_cmd = "google-chrome --incognito "
                                 "--no-first-run "
                                 "--no-default-browser-check "
                                 "--disable-gpu "
                                 "--disable-software-rasterizer "
                                 "--disable-features=VizDisplayCompositor "
                                 "--user-data-dir=" + user_profile + " " +
                                 url;

        std::cout << "Launching Chrome for trace: " << trace << std::endl;
        pid_t chrome_pid = launch_chrome(chrome_cmd);

        // Wait a bit for page to load
        //this_thread::sleep_for(seconds(3));

        long prev_energy = read_rapl(RAPL_Package);
        auto start_time = high_resolution_clock::now();

        for (int i = 0; i < num_samples; ++i) {
            auto now = high_resolution_clock::now();
            long curr_energy = read_rapl(RAPL_Package);
            //cout<< curr_energy;
            long diff = curr_energy - prev_energy;
            prev_energy = curr_energy;
            traces[trace][i] = diff;



            this_thread::sleep_until(start_time + microseconds(1000 * (i + 1)));
        }

        // Kill Chrome process group (includes all child processes)
        killpg(chrome_pid, SIGKILL);
        waitpid(chrome_pid, nullptr, 0);

        // Cleanup profile
        std::string cleanup = "rm -rf " + user_profile;
        system(cleanup.c_str());

        this_thread::sleep_for(seconds(2)); // allow cleanup before next trace
    }

    // Compute mean and variance
    vector<long> mean_trace(num_samples, 0);
    vector<double> variance_trace(num_samples, 0.0);
    
        for (int trace = 0; trace < num_traces; ++trace) {
        for (int i = 0; i < num_samples; ++i) {
        int j=i;
           if(traces[trace][j] == 0 && j > 0) {         
              traces[trace][j] = traces[trace][j - 1];
          } 
         }
        }

    for (int i = 0; i < num_samples; ++i) {
        long sum = 0;
        for (int trace = 0; trace < num_traces; ++trace) {
            sum += traces[trace][i];
        }
        mean_trace[i] = sum / num_traces;

        double var_sum = 0.0;
        for (int trace = 0; trace < num_traces; ++trace) {
            var_sum += pow(traces[trace][i] - mean_trace[i], 2);
        }
        variance_trace[i] = var_sum / num_traces;
    }

    // Write data to CSV
    string csv_filename = website + "_power_traces.csv";
    ofstream csv_file(csv_filename);

    if (!csv_file.is_open()) {
        cerr << "Failed to open file: " << csv_filename << endl;
        return;
    }

    csv_file << "Sample_ID,Website";
    for (int i = 1; i <= num_traces; ++i)
        csv_file << ",Trace_" << i;
    csv_file << ",Mean,Variance\n";

    for (int i = 0; i < num_samples; ++i) {
        csv_file << i << "," << website;
        for (int trace = 0; trace < num_traces; ++trace)
            csv_file << "," << traces[trace][i];
        csv_file << "," << mean_trace[i] << "," << variance_trace[i] << "\n";
        csv_file.flush();
    }

    csv_file.close();
    cout << "Finished recording power for " << website << ". Data saved to " << csv_filename << endl;
}

int main() {
    vector<pair<string, string>> websites = {
        {"360.cn", "https://www.360.cn"}, {"Aliexpress.com", "https://www.aliexpress.com"},
        {"Alipay.com", "https://www.alipay.com"}, {"Amazon.com", "https://www.amazon.com"},
        {"Baidu.com", "https://www.baidu.com"}, {"Bing.com", "https://www.bing.com"},
        {"Blogger.com", "https://www.blogger.com"}, {"China.com.cn", "https://www.china.com.cn"},
        {"Csdn.net", "https://www.csdn.net"}, {"Ebay.com", "https://www.ebay.com"},
        {"Facebook.com", "https://www.facebook.com"}, {"Google.com", "https://www.google.com"},
        {"Instagram.com", "https://www.instagram.com"}, {"Jd.com", "https://www.jd.com"},
        {"Live.com", "https://www.live.com"}, {"Microsoft.com", "https://www.microsoft.com"},
        {"Myshopify.com", "https://www.shopify.com"}, {"Naver.com", "https://www.naver.com"},
        {"Netflix.com", "https://www.netflix.com"}, {"Office.com", "https://www.office.com"},
        {"Okezone.com", "https://www.okezone.com"}, {"Qq.com", "https://www.qq.com"},
        {"Reddit.com", "https://www.reddit.com"}, {"Sina.com.cn", "https://www.sina.com.cn"},
        {"Sohu.com", "https://www.sohu.com"}, {"Taobao.com", "https://www.taobao.com"},
        {"Tianya.cn", "https://www.tianya.cn"}, {"Tmall.com", "https://www.tmall.com"},
        {"Tribunnews.com", "https://www.tribunnews.com"}, {"Twitch.tv", "https://www.twitch.tv"},
        {"Vk.com", "https://www.vk.com"}, {"Weibo.com", "https://www.weibo.com"},
        {"Wikipedia.org", "https://www.wikipedia.org"}, {"Xinhuanet.com", "https://www.xinhuanet.com"},
        {"Yahoo.com", "https://www.yahoo.com"}, {"Youtube.com", "https://www.youtube.com"},
        {"Zoom.us", "https://www.zoom.us"}
    };

    for (const auto& [website, url] : websites) {
        measure_power(website, url);
    }

    cout << "All websites measured successfully!" << endl;
    return 0;
}










