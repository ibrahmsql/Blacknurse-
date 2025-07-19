/**
 * BlackNurse 2.0 - Performance Monitor
 * 
 * Real-time performance monitoring with enhanced metrics,
 * system resource tracking, and beautiful console output.
 */

#pragma once

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <deque>
#include <numeric>
#include <algorithm>
#include <mutex>

#ifdef __APPLE__
#include <mach/mach.h>
#include <sys/sysctl.h>
#elif __linux__
#include <sys/sysinfo.h>
#include <fstream>
#endif

#include "common/config.hpp"
#include "common/logger.hpp"

namespace BlackNurse {

/**
 * System resource information
 */
struct SystemInfo {
    double cpu_usage = 0.0;
    double memory_usage = 0.0;
    uint64_t memory_total = 0;
    uint64_t memory_available = 0;
    uint32_t cpu_cores = 0;
    double load_average = 0.0;
};

/**
 * Performance metrics collector
 */
class PerformanceMonitor {
public:
    explicit PerformanceMonitor(uint32_t update_interval_seconds = 1)
        : update_interval_(std::chrono::seconds(update_interval_seconds)),
          running_(false), total_packets_(0), total_bytes_(0), total_errors_(0) {
        
        // Initialize system info
        update_system_info();
        
        // Reserve space for history
        // deque doesn't have reserve method, it grows dynamically
    }
    
    ~PerformanceMonitor() {
        stop();
    }
    
    void start() {
        if (running_.exchange(true)) {
            return;
        }
        
        start_time_ = std::chrono::steady_clock::now();
        last_update_ = start_time_;
        
        monitor_thread_ = std::thread(&PerformanceMonitor::monitor_loop, this);
        blacknurse::Logger::info("Performance monitor started");
    }
    
    void stop() {
        if (!running_.exchange(false)) {
            return;
        }
        
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
        
        blacknurse::Logger::info("Performance monitor stopped");
    }
    
    void update(const AttackStats& stats) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Manually copy atomic values
        current_stats_.packets_sent = stats.packets_sent.load();
        current_stats_.packets_failed = stats.packets_failed.load();
        current_stats_.bytes_sent = stats.bytes_sent.load();
        current_stats_.connections_established = stats.connections_established.load();
        current_stats_.connections_failed = stats.connections_failed.load();
        current_stats_.current_rate = stats.current_rate.load();
        current_stats_.avg_response_time = stats.avg_response_time.load();
        current_stats_.start_time = stats.start_time;
        current_stats_.last_update = stats.last_update;
        
        // Update totals
        total_packets_ = stats.packets_sent.load();
        total_bytes_ = stats.bytes_sent.load();
        total_errors_ = stats.packets_failed.load();
    }
    
    void print_final_stats() const {
        print_summary();
    }
    
    void print_summary() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
        
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "📊 BLACKNURSE PERFORMANCE SUMMARY\n";
        std::cout << std::string(80, '=') << "\n";
        
        std::cout << std::left << std::setw(25) << "Duration:" 
                  << format_duration(duration) << "\n";
        std::cout << std::left << std::setw(25) << "Total Packets:" 
                  << format_number(total_packets_) << "\n";
        std::cout << std::left << std::setw(25) << "Total Bytes:" 
                  << format_bytes(total_bytes_) << "\n";
        std::cout << std::left << std::setw(25) << "Average Rate:" 
                  << format_number(duration > 0 ? total_packets_ / duration : 0) << " pps\n";
        std::cout << std::left << std::setw(25) << "Peak Rate:" 
                  << format_number(get_peak_rate()) << " pps\n";
        std::cout << std::left << std::setw(25) << "Total Errors:" 
                  << format_number(total_errors_) << "\n";
        std::cout << std::left << std::setw(25) << "Error Rate:" 
                  << std::fixed << std::setprecision(2) 
                  << (total_packets_ > 0 ? (double)total_errors_ / total_packets_ * 100 : 0) << "%\n";
        
        std::cout << std::string(80, '=') << "\n";
    }
    
private:
    void monitor_loop() {
        while (running_.load()) {
            auto now = std::chrono::steady_clock::now();
            
            if (now - last_update_ >= update_interval_) {
                update_display();
                update_system_info();
                last_update_ = now;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void update_display() {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
        
        // Calculate current rate
        double current_rate = 0.0;
        if (!packet_history_.empty()) {
            auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_packet_time_).count();
            if (interval > 0) {
                current_rate = (current_stats_.packets_sent - last_packet_count_) * 1000.0 / interval;
            }
        }
        
        // Update history
        packet_history_.push_back(current_stats_.packets_sent);
        rate_history_.push_back(current_rate);
        
        // Keep history size manageable
        if (packet_history_.size() > 300) {
            packet_history_.pop_front();
            rate_history_.pop_front();
        }
        
        last_packet_count_ = current_stats_.packets_sent;
        last_packet_time_ = now;
        
        // Clear screen and print header
        std::cout << "\033[2J\033[H"; // Clear screen and move cursor to top
        print_header();
        print_stats(duration, current_rate);
        print_system_info();
        print_rate_graph();
    }
    
    void print_header() const {
        std::cout << "\n";
        std::cout << "🔥 BlackNurse 2.0 - Real-time Performance Monitor 🔥\n";
        std::cout << std::string(80, '-') << "\n";
    }
    
    void print_stats(uint64_t duration, double current_rate) const {
        std::cout << "📈 ATTACK STATISTICS\n";
        std::cout << std::string(40, '-') << "\n";
        
        std::cout << std::left << std::setw(20) << "⏱️  Duration:" 
                  << format_duration(duration) << "\n";
        std::cout << std::left << std::setw(20) << "📦 Packets Sent:" 
                  << format_number(current_stats_.packets_sent) << "\n";
        std::cout << std::left << std::setw(20) << "💾 Bytes Sent:" 
                  << format_bytes(current_stats_.bytes_sent) << "\n";
        std::cout << std::left << std::setw(20) << "⚡ Current Rate:" 
                  << format_number(static_cast<uint64_t>(current_rate)) << " pps\n";
        std::cout << std::left << std::setw(20) << "📊 Average Rate:" 
                  << format_number(static_cast<uint64_t>(current_stats_.current_rate.load())) << " pps\n";
        std::cout << std::left << std::setw(20) << "❌ Errors:" 
                  << format_number(current_stats_.packets_failed.load()) << "\n";
        
        double error_rate = current_stats_.packets_sent.load() > 0 ? 
                            (double)current_stats_.packets_failed.load() / current_stats_.packets_sent.load() * 100 : 0;
        std::cout << std::left << std::setw(20) << "📉 Error Rate:" 
                  << std::fixed << std::setprecision(2) << error_rate << "%\n";
        
        std::cout << "\n";
    }
    
    void print_system_info() const {
        std::cout << "🖥️  SYSTEM RESOURCES\n";
        std::cout << std::string(40, '-') << "\n";
        
        std::cout << std::left << std::setw(20) << "🔥 CPU Usage:" 
                  << std::fixed << std::setprecision(1) << system_info_.cpu_usage << "%\n";
        std::cout << std::left << std::setw(20) << "💾 Memory Usage:" 
                  << std::fixed << std::setprecision(1) << system_info_.memory_usage << "%\n";
        std::cout << std::left << std::setw(20) << "⚙️  CPU Cores:" 
                  << system_info_.cpu_cores << "\n";
        std::cout << std::left << std::setw(20) << "📈 Load Average:" 
                  << std::fixed << std::setprecision(2) << system_info_.load_average << "\n";
        
        std::cout << "\n";
    }
    
    void print_rate_graph() const {
        if (rate_history_.size() < 2) return;
        
        std::cout << "📊 PACKET RATE GRAPH (last 60 seconds)\n";
        std::cout << std::string(60, '-') << "\n";
        
        // Get last 60 data points
        size_t graph_size = std::min(size_t(60), rate_history_.size());
        std::vector<double> graph_data(rate_history_.end() - graph_size, rate_history_.end());
        
        if (graph_data.empty()) return;
        
        // Find min/max for scaling
        auto [min_it, max_it] = std::minmax_element(graph_data.begin(), graph_data.end());
        double min_rate = *min_it;
        double max_rate = *max_it;
        
        if (max_rate == min_rate) max_rate = min_rate + 1;
        
        // Print graph
        const int graph_height = 10;
        for (int row = graph_height - 1; row >= 0; --row) {
            double threshold = min_rate + (max_rate - min_rate) * row / (graph_height - 1);
            
            std::cout << std::setw(8) << std::fixed << std::setprecision(0) << threshold << " │";
            
            for (double rate : graph_data) {
                if (rate >= threshold) {
                    std::cout << "█";
                } else {
                    std::cout << " ";
                }
            }
            std::cout << "\n";
        }
        
        std::cout << std::string(10, ' ') << std::string(graph_size, '-') << "\n";
        std::cout << std::string(10, ' ') << "Time (seconds ago)\n\n";
    }
    
    void update_system_info() {
#ifdef __APPLE__
        update_system_info_macos();
#elif __linux__
        update_system_info_linux();
#endif
    }
    
#ifdef __APPLE__
    void update_system_info_macos() {
        // Get CPU usage
        host_cpu_load_info_data_t cpu_info;
        mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
        if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, 
                           (host_info_t)&cpu_info, &count) == KERN_SUCCESS) {
            
            static uint32_t prev_user = 0, prev_system = 0, prev_idle = 0;
            uint32_t user = cpu_info.cpu_ticks[CPU_STATE_USER];
            uint32_t system = cpu_info.cpu_ticks[CPU_STATE_SYSTEM];
            uint32_t idle = cpu_info.cpu_ticks[CPU_STATE_IDLE];
            
            uint32_t total_delta = (user + system + idle) - (prev_user + prev_system + prev_idle);
            uint32_t used_delta = (user + system) - (prev_user + prev_system);
            
            if (total_delta > 0) {
                system_info_.cpu_usage = (double)used_delta / total_delta * 100.0;
            }
            
            prev_user = user;
            prev_system = system;
            prev_idle = idle;
        }
        
        // Get memory usage
        vm_statistics64_data_t vm_stat;
        count = HOST_VM_INFO64_COUNT;
        if (host_statistics64(mach_host_self(), HOST_VM_INFO64, 
                             (host_info64_t)&vm_stat, &count) == KERN_SUCCESS) {
            
            uint64_t page_size = 4096; // Assume 4KB pages
            uint64_t total_memory = (vm_stat.free_count + vm_stat.active_count + 
                                   vm_stat.inactive_count + vm_stat.wire_count) * page_size;
            uint64_t used_memory = (vm_stat.active_count + vm_stat.wire_count) * page_size;
            
            system_info_.memory_total = total_memory;
            system_info_.memory_usage = total_memory > 0 ? 
                                       (double)used_memory / total_memory * 100.0 : 0;
        }
        
        // Get CPU core count
        size_t size = sizeof(system_info_.cpu_cores);
        sysctlbyname("hw.ncpu", &system_info_.cpu_cores, &size, NULL, 0);
        
        // Get load average
        double load[3];
        if (getloadavg(load, 3) != -1) {
            system_info_.load_average = load[0];
        }
    }
#endif
    
#ifdef __linux__
    void update_system_info_linux() {
        // Get CPU usage from /proc/stat
        std::ifstream stat_file("/proc/stat");
        if (stat_file.is_open()) {
            std::string line;
            std::getline(stat_file, line);
            
            std::istringstream iss(line);
            std::string cpu;
            uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
            
            iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
            
            static uint64_t prev_total = 0, prev_idle_total = 0;
            uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
            uint64_t idle_total = idle + iowait;
            
            uint64_t total_delta = total - prev_total;
            uint64_t idle_delta = idle_total - prev_idle_total;
            
            if (total_delta > 0) {
                system_info_.cpu_usage = (double)(total_delta - idle_delta) / total_delta * 100.0;
            }
            
            prev_total = total;
            prev_idle_total = idle_total;
        }
        
        // Get memory usage from /proc/meminfo
        std::ifstream meminfo("/proc/meminfo");
        if (meminfo.is_open()) {
            std::string line;
            uint64_t mem_total = 0, mem_available = 0;
            
            while (std::getline(meminfo, line)) {
                if (line.find("MemTotal:") == 0) {
                    std::istringstream iss(line);
                    std::string label;
                    iss >> label >> mem_total;
                    mem_total *= 1024; // Convert from KB to bytes
                } else if (line.find("MemAvailable:") == 0) {
                    std::istringstream iss(line);
                    std::string label;
                    iss >> label >> mem_available;
                    mem_available *= 1024; // Convert from KB to bytes
                }
            }
            
            system_info_.memory_total = mem_total;
            system_info_.memory_available = mem_available;
            if (mem_total > 0) {
                system_info_.memory_usage = (double)(mem_total - mem_available) / mem_total * 100.0;
            }
        }
        
        // Get CPU core count
        system_info_.cpu_cores = std::thread::hardware_concurrency();
        
        // Get load average
        double load[3];
        if (getloadavg(load, 3) != -1) {
            system_info_.load_average = load[0];
        }
    }
#endif
    
    std::string format_number(uint64_t number) const {
        if (number >= 1000000000) {
            return std::to_string(number / 1000000000) + "B";
        } else if (number >= 1000000) {
            return std::to_string(number / 1000000) + "M";
        } else if (number >= 1000) {
            return std::to_string(number / 1000) + "K";
        }
        return std::to_string(number);
    }
    
    std::string format_bytes(uint64_t bytes) const {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        int unit = 0;
        double size = static_cast<double>(bytes);
        
        while (size >= 1024 && unit < 4) {
            size /= 1024;
            unit++;
        }
        
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
        return oss.str();
    }
    
    std::string format_duration(uint64_t seconds) const {
        uint64_t hours = seconds / 3600;
        uint64_t minutes = (seconds % 3600) / 60;
        uint64_t secs = seconds % 60;
        
        std::ostringstream oss;
        if (hours > 0) {
            oss << hours << "h " << minutes << "m " << secs << "s";
        } else if (minutes > 0) {
            oss << minutes << "m " << secs << "s";
        } else {
            oss << secs << "s";
        }
        return oss.str();
    }
    
    uint64_t get_peak_rate() const {
        if (rate_history_.empty()) return 0;
        return static_cast<uint64_t>(*std::max_element(rate_history_.begin(), rate_history_.end()));
    }
    
    std::chrono::seconds update_interval_;
    std::atomic<bool> running_;
    std::thread monitor_thread_;
    
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point last_update_;
    std::chrono::steady_clock::time_point last_packet_time_;
    
    AttackStats current_stats_;
    mutable std::mutex stats_mutex_;
    
    uint64_t total_packets_;
    uint64_t total_bytes_;
    uint64_t total_errors_;
    uint64_t last_packet_count_ = 0;
    
    SystemInfo system_info_;
    
    std::deque<uint64_t> packet_history_;
    std::deque<double> rate_history_;
};

} // namespace blacknurse