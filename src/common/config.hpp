/**
 * BlackNurse 2.0 - ICMP Configuration
 * 
 * Configuration structure for ICMP flood attacks
 */

#pragma once

#include <string>
#include <thread>
#include <chrono>
#include <atomic>

namespace blacknurse {

/**
 * Configuration structure for BlackNurse attack parameters
 */
struct Config {
    // Target configuration
    std::string target_ip;
    std::string source_ip = "";
    std::string protocol = "icmp"; // icmp, tcp, udp, http, https, dns
    uint16_t target_port = 80;
    
    // Attack parameters
    uint32_t packets_per_second = 1000;
    uint32_t rate_limit = 1000; // alias for packets_per_second
    uint32_t payload_size = 32;
    uint32_t duration_seconds = 0; // 0 = unlimited
    
    // Threading configuration
    uint32_t thread_count = std::thread::hardware_concurrency();
    uint32_t threads = std::thread::hardware_concurrency(); // alias for thread_count
    
    // Enhanced features
    bool use_gpu = false;
    bool stealth_mode = false;
    bool adaptive_rate = false;
    bool waf_bypass = false;
    bool verbose = false;
    
    // Monitoring
    uint32_t stats_interval = 1; // seconds
    
    // Network configuration
    uint16_t source_port_min = 1024;
    uint16_t source_port_max = 65535;
    uint8_t ttl = 64;
    
    // ICMP specific
    uint8_t icmp_type = 3;  // Destination Unreachable
    uint8_t icmp_code = 3;  // Port Unreachable
    
    // Rate limiting
    uint32_t max_pps_per_thread = 10000;
    uint32_t burst_size = 100;
    
    // Validation
    bool validate() const {
        if (target_ip.empty()) return false;
        if (thread_count == 0 || thread_count > 256) return false;
        if (packets_per_second == 0 || packets_per_second > 1000000) return false;
        if (payload_size > 1400) return false;
        return true;
    }
    
    // Auto-tune based on system capabilities
    void auto_tune() {
        if (thread_count == 0) {
            thread_count = std::thread::hardware_concurrency();
        }
        
        // Limit thread count based on rate
        uint32_t optimal_threads = (packets_per_second + max_pps_per_thread - 1) / max_pps_per_thread;
        if (optimal_threads < thread_count) {
            thread_count = optimal_threads;
        }
        
        // Ensure minimum thread count
        if (thread_count < 1) {
            thread_count = 1;
        }
    }
};

/**
 * Attack statistics structure
 */
struct AttackStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> packets_failed{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> retries{0};
    
    std::atomic<double> avg_pps{0.0};
    std::atomic<double> current_pps{0.0};
    std::atomic<double> cpu_usage{0.0};
    std::atomic<double> memory_usage{0.0};
    
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_update;
    
    void reset() {
        packets_sent = 0;
        bytes_sent = 0;
        errors = 0;
        retries = 0;
        avg_pps = 0.0;
        current_pps = 0.0;
        cpu_usage = 0.0;
        memory_usage = 0.0;
        start_time = std::chrono::steady_clock::now();
        last_update = start_time;
    }
    
    void update_rates() {
        auto now = std::chrono::steady_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        auto interval_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count();
        
        if (total_duration > 0) {
            avg_pps = (packets_sent * 1000.0) / total_duration;
        }
        
        last_update = now;
    }
};

} // namespace blacknurse