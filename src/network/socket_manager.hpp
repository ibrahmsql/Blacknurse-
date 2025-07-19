/**
 * BlackNurse 2.0 - Socket Manager
 * 
 * High-performance socket management with connection pooling,
 * error handling, and platform-specific optimizations.
 */

#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>

#include "common/config.hpp"
#include "common/logger.hpp"
#include "packet_generator.hpp"

namespace blacknurse {

/**
 * Socket wrapper for thread-safe operations
 */
class Socket {
public:
    Socket() : fd_(-1), last_error_(0) {}
    
    ~Socket() {
        close();
    }
    
    bool create_raw_socket() {
        fd_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (fd_ < 0) {
            last_error_ = errno;
            return false;
        }
        
        // Set socket options for better performance
        int on = 1;
        if (setsockopt(fd_, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            last_error_ = errno;
            Logger::warning("Failed to set IP_HDRINCL: " + std::string(strerror(errno)));
        }
        
        // Set socket buffer sizes
        int buffer_size = 1024 * 1024; // 1MB
        setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        
        // Set non-blocking mode
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
        }
        
        return true;
    }
    
    bool send_packet(const Packet& packet, const struct sockaddr_in& dest) {
        if (fd_ < 0) {
            return false;
        }
        
        ssize_t sent = sendto(fd_, packet.raw(), packet.size(), 0,
                             reinterpret_cast<const struct sockaddr*>(&dest),
                             sizeof(dest));
        
        if (sent < 0) {
            last_error_ = errno;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Non-blocking socket would block, try again later
                return false;
            }
            if (errno == ENOBUFS) {
                // Buffer full, back off
                return false;
            }
            return false;
        }
        
        return sent == static_cast<ssize_t>(packet.size());
    }
    
    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
    
    bool is_valid() const {
        return fd_ >= 0;
    }
    
    int get_last_error() const {
        return last_error_;
    }
    
    int get_fd() const {
        return fd_;
    }
    
private:
    int fd_;
    int last_error_;
};

/**
 * High-performance socket manager with connection pooling
 */
class SocketManager {
public:
    explicit SocketManager(const Config& config) 
        : config_(config), socket_pool_index_(0) {
        
        // Setup destination address
        std::memset(&dest_addr_, 0, sizeof(dest_addr_));
        dest_addr_.sin_family = AF_INET;
        if (inet_aton(config_.target_ip.c_str(), &dest_addr_.sin_addr) == 0) {
            throw std::invalid_argument("Invalid target IP: " + config_.target_ip);
        }
        
        // Create socket pool for better performance
        size_t pool_size = std::max(1u, config_.thread_count);
        socket_pool_.resize(pool_size);
        
        for (size_t i = 0; i < pool_size; ++i) {
            auto socket = std::make_unique<Socket>();
            if (!socket->create_raw_socket()) {
                throw std::runtime_error("Failed to create raw socket: " + 
                                        std::string(strerror(socket->get_last_error())));
            }
            socket_pool_[i] = std::move(socket);
        }
        
        Logger::info("Socket manager initialized with " + std::to_string(pool_size) + " sockets");
    }
    
    ~SocketManager() {
        for (auto& socket : socket_pool_) {
            if (socket) {
                socket->close();
            }
        }
    }
    
    bool send_packet(const Packet& packet) {
        // Get socket from pool (round-robin)
        size_t index = socket_pool_index_.fetch_add(1) % socket_pool_.size();
        auto& socket = socket_pool_[index];
        
        if (!socket || !socket->is_valid()) {
            // Try to recreate socket
            socket = std::make_unique<Socket>();
            if (!socket->create_raw_socket()) {
                Logger::error("Failed to recreate socket: " + 
                             std::string(strerror(socket->get_last_error())));
                return false;
            }
        }
        
        bool success = socket->send_packet(packet, dest_addr_);
        
        if (!success) {
            int error = socket->get_last_error();
            if (error == ENOBUFS) {
                // Buffer full, implement backoff
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            } else if (error == EPERM) {
                Logger::error("Permission denied. Run as root or with CAP_NET_RAW capability.");
            }
        }
        
        return success;
    }
    
    /**
     * Send multiple packets in a batch for better performance
     */
    size_t send_packet_batch(const std::vector<Packet>& packets) {
        size_t sent_count = 0;
        
        for (const auto& packet : packets) {
            if (send_packet(packet)) {
                sent_count++;
            } else {
                // If one packet fails, implement exponential backoff
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        }
        
        return sent_count;
    }
    
    /**
     * Get socket statistics
     */
    struct SocketStats {
        size_t active_sockets = 0;
        size_t failed_sockets = 0;
        size_t total_sends = 0;
        size_t failed_sends = 0;
    };
    
    SocketStats get_stats() const {
        SocketStats stats;
        
        for (const auto& socket : socket_pool_) {
            if (socket && socket->is_valid()) {
                stats.active_sockets++;
            } else {
                stats.failed_sockets++;
            }
        }
        
        return stats;
    }
    
    /**
     * Optimize socket settings for high-performance sending
     */
    void optimize_for_performance() {
        for (auto& socket : socket_pool_) {
            if (socket && socket->is_valid()) {
                int fd = socket->get_fd();
                
                // Disable Nagle's algorithm
                int flag = 1;
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                
                // Set high priority (not available on macOS)
#ifndef __APPLE__
                int priority = 6;
                setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
#endif
                
                // Set larger buffer sizes
                int buffer_size = 2 * 1024 * 1024; // 2MB
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
                
                // Enable timestamp options for better debugging
                int timestamp = 1;
                setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp, sizeof(timestamp));
            }
        }
        
        Logger::info("Socket optimization applied");
    }
    
private:
    const Config& config_;
    struct sockaddr_in dest_addr_;
    std::vector<std::unique_ptr<Socket>> socket_pool_;
    std::atomic<size_t> socket_pool_index_;
};

} // namespace blacknurse