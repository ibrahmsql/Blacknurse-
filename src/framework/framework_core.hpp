/**
 * BlackNurse Framework  - Core Framework Engine
 * 
 * Comprehensive multi-protocol penetration testing framework
 * Supporting ICMP, TCP, UDP, HTTP/HTTPS, DNS, and WAF bypass techniques
 */

#pragma once

#include <vector>
#include <memory>
#include <string>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <queue>
#include <random>
#include <set>

#include "../common/config.hpp"
#include "../common/logger.hpp"

namespace BlackNurse {

// Protocol types supported by the framework
enum class ProtocolType {
    ICMP,
    TCP,
    UDP,
    HTTP,
    HTTPS,
    DNS,
    CUSTOM
};

// Attack types for different protocols
enum class AttackType {
    // ICMP attacks
    ICMP_FLOOD,
    ICMP_FRAGMENTATION,
    ICMP_REDIRECT,
    
    // TCP attacks
    TCP_SYN_FLOOD,
    TCP_ACK_FLOOD,
    TCP_RST_FLOOD,
    TCP_FIN_FLOOD,
    TCP_SLOWLORIS,
    TCP_SOCKSTRESS,
    
    // UDP attacks
    UDP_FLOOD,
    UDP_FRAGMENTATION,
    UDP_AMPLIFICATION,
    
    // HTTP/HTTPS attacks
    HTTP_GET_FLOOD,
    HTTP_POST_FLOOD,
    HTTP_SLOWLORIS,
    HTTP_RUDY,
    HTTP_BYTERANGE,
    HTTPS_RENEGOTIATION,
    
    // DNS attacks
    DNS_AMPLIFICATION,
    DNS_FLOOD,
    DNS_CACHE_POISONING,
    
    // WAF bypass techniques
    WAF_EVASION_ENCODING,
    WAF_EVASION_FRAGMENTATION,
    WAF_EVASION_OBFUSCATION,
    
    // Enhanced techniques
    LAYER7_SLOWREAD,
    LAYER7_SLOWPOST,
    MIXED_PROTOCOL_ATTACK
};

// Evasion techniques
enum class EvasionTechnique {
    NONE,
    IP_SPOOFING,
    TTL_VARIATION,
    PACKET_FRAGMENTATION,
    TIMING_VARIATION,
    PAYLOAD_OBFUSCATION,
    PROTOCOL_TUNNELING,
    TRAFFIC_SHAPING,
    DECOY_PACKETS
};

// Target information structure
struct Target {
    std::string ip;
    uint16_t port = 0;
    ProtocolType protocol = ProtocolType::ICMP;
    std::string hostname;
    std::vector<std::string> additional_ips;
    bool is_load_balanced = false;
    std::unordered_map<std::string, std::string> metadata;
};

// Attack configuration
struct AttackConfig {
    AttackType type = AttackType::ICMP_FLOOD;
    uint32_t rate_pps = 1000;
    uint32_t duration_seconds = 0;
    uint32_t thread_count = 0; // 0 = auto-detect
    uint32_t payload_size = 32;
    bool use_gpu = false;
    bool stealth_mode = false;
    std::vector<EvasionTechnique> evasion_techniques;
    std::unordered_map<std::string, std::string> custom_headers;
    std::string user_agent;
    std::vector<std::string> proxy_list;
    bool adaptive_rate = true;
    double rate_multiplier = 1.0;
};

// Attack statistics
struct AttackStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_failed{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> connections_established{0};
    std::atomic<uint64_t> connections_failed{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<double> current_rate{0.0};
    std::atomic<double> avg_response_time{0.0};
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_update;
    std::mutex stats_mutex;
    
    // Default constructor
    AttackStats() = default;
    
    // Move constructor
    AttackStats(AttackStats&& other) noexcept
        : packets_sent(other.packets_sent.load()),
          packets_failed(other.packets_failed.load()),
          bytes_sent(other.bytes_sent.load()),
          connections_established(other.connections_established.load()),
          connections_failed(other.connections_failed.load()),
          errors(other.errors.load()),
          current_rate(other.current_rate.load()),
          avg_response_time(other.avg_response_time.load()),
          start_time(std::move(other.start_time)),
          last_update(std::move(other.last_update)) {}
    
    // Move assignment operator
    AttackStats& operator=(AttackStats&& other) noexcept {
        if (this != &other) {
            packets_sent.store(other.packets_sent.load());
            packets_failed.store(other.packets_failed.load());
            bytes_sent.store(other.bytes_sent.load());
            connections_established.store(other.connections_established.load());
            connections_failed.store(other.connections_failed.load());
            errors.store(other.errors.load());
            current_rate.store(other.current_rate.load());
            avg_response_time.store(other.avg_response_time.load());
            start_time = std::move(other.start_time);
            last_update = std::move(other.last_update);
        }
        return *this;
    }
};

// Forward declarations
class ProtocolHandler;
class EvasionEngine;
class PayloadGenerator;
class TrafficAnalyzer;

/**
 * Main Framework Core Class
 * Orchestrates all attack modules and provides unified interface
 */
class FrameworkCore {
public:
    FrameworkCore();
    ~FrameworkCore();
    
    // Framework initialization
    bool initialize(const blacknurse::Config& config);
    void shutdown();
    
    // Target management
    bool add_target(const Target& target);
    bool remove_target(const std::string& target_id);
    std::vector<Target> get_targets() const;
    
    // Attack execution
    bool start_attack(const AttackConfig& config);
    bool stop_attack();
    bool pause_attack();
    bool resume_attack();
    
    // Real-time control
    bool adjust_rate(double multiplier);
    bool switch_attack_type(AttackType new_type);
    bool enable_evasion(EvasionTechnique technique);
    bool disable_evasion(EvasionTechnique technique);
    
    // Statistics and monitoring
    AttackStats get_stats() const;
    std::vector<std::string> get_live_metrics() const;
    bool export_results(const std::string& filename) const;
    
    // Protocol handlers
    bool register_protocol_handler(ProtocolType type, std::unique_ptr<ProtocolHandler> handler);
    ProtocolHandler* get_protocol_handler(ProtocolType type);
    
    // Enhanced features
    bool enable_traffic_analysis();
    bool enable_adaptive_learning();
    bool load_attack_profile(const std::string& profile_path);
    bool save_attack_profile(const std::string& profile_path) const;
    
    // WAF detection and bypass
    bool detect_waf(const Target& target);
    std::vector<EvasionTechnique> suggest_bypass_techniques(const Target& target);
    
private:
    // Core components
    std::unique_ptr<EvasionEngine> evasion_engine_;
    std::unique_ptr<PayloadGenerator> payload_generator_;
    std::unique_ptr<TrafficAnalyzer> traffic_analyzer_;
    
    // Protocol handlers
    std::unordered_map<ProtocolType, std::unique_ptr<ProtocolHandler>> protocol_handlers_;
    
    // Target management
    std::vector<Target> targets_;
    mutable std::mutex targets_mutex_;
    
    // Attack state
    std::atomic<bool> attack_running_{false};
    std::atomic<bool> attack_paused_{false};
    AttackConfig current_config_;
    AttackStats stats_;
    
    // Worker threads
    std::vector<std::thread> worker_threads_;
    std::atomic<bool> shutdown_requested_{false};
    
    // Thread synchronization
    std::mutex control_mutex_;
    std::condition_variable control_cv_;
    
    // Rate control
    std::atomic<double> target_rate_{1000.0};
    std::chrono::steady_clock::time_point last_rate_adjustment_;
    
    // Random number generation
    mutable std::random_device rd_;
    mutable std::mt19937 gen_;
    
    // Internal methods
    void worker_thread_main(size_t thread_id);
    void stats_update_thread();
    void adaptive_rate_controller();
    bool validate_config(const AttackConfig& config) const;
    void cleanup_resources();
    
    // Protocol-specific attack execution
    bool execute_icmp_attack(const Target& target, const AttackConfig& config);
    bool execute_tcp_attack(const Target& target, const AttackConfig& config);
    bool execute_udp_attack(const Target& target, const AttackConfig& config);
    bool execute_http_attack(const Target& target, const AttackConfig& config);
    bool execute_dns_attack(const Target& target, const AttackConfig& config);
    
    // Utility methods
    std::string generate_session_id() const;
    void log_attack_event(const std::string& event, const std::string& details = "");
};

/**
 * Protocol Handler Base Class
 * Abstract interface for protocol-specific implementations
 */
class ProtocolHandler {
public:
    virtual ~ProtocolHandler() = default;
    
    virtual bool initialize(const blacknurse::Config& config) = 0;
    virtual bool execute_attack(const Target& target, const AttackConfig& config, AttackStats& stats) = 0;
    virtual bool supports_attack_type(AttackType type) const = 0;
    virtual std::vector<EvasionTechnique> get_supported_evasions() const = 0;
    virtual bool validate_target(const Target& target) const = 0;
    virtual void cleanup() = 0;
    
protected:
    blacknurse::Config config_;
    std::atomic<bool> active_{false};
};

/**
 * Evasion Engine
 * Handles various evasion and stealth techniques
 */
class EvasionEngine {
public:
    EvasionEngine();
    ~EvasionEngine();
    
    bool initialize();
    void shutdown();
    
    // Evasion technique management
    bool enable_technique(EvasionTechnique technique);
    bool disable_technique(EvasionTechnique technique);
    bool is_enabled(EvasionTechnique technique) const;
    
    // Packet modification
    bool apply_evasions(std::vector<uint8_t>& packet, const Target& target);
    bool apply_ip_spoofing(std::vector<uint8_t>& packet);
    bool apply_ttl_variation(std::vector<uint8_t>& packet);
    bool apply_fragmentation(std::vector<uint8_t>& packet);
    bool apply_payload_obfuscation(std::vector<uint8_t>& packet);
    
    // Timing evasion
    std::chrono::microseconds get_next_delay();
    void reset_timing_pattern();
    
private:
    std::set<EvasionTechnique> enabled_techniques_;
    std::mutex techniques_mutex_;
    
    // Spoofing pools
    std::vector<std::string> spoofed_ips_;
    std::vector<uint8_t> ttl_values_;
    
    // Timing patterns
    std::vector<std::chrono::microseconds> timing_patterns_;
    size_t current_timing_index_;
    
    // Random generators
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<> ip_dist_;
    std::uniform_int_distribution<> ttl_dist_;
    std::uniform_int_distribution<> timing_dist_;
};

} // namespace BlackNurse