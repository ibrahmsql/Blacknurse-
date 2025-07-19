#include "framework_core.hpp"
#include "../common/logger.hpp"

using namespace blacknurse;
#include <iostream>
#include <thread>
#include <chrono>

namespace BlackNurse {

FrameworkCore::FrameworkCore(const blacknurse::Config& config) 
    : config_(config), running_(false), stats_{} {
    
    // Initialize protocol handlers based on configuration
    if (config_.protocol == "http" || config_.protocol == "https") {
        http_handler_ = std::make_unique<HttpHandler>(config_);
    }
    else if (config_.protocol == "tcp") {
        tcp_handler_ = std::make_unique<TcpHandler>(config_);
    }
    else if (config_.protocol == "udp") {
        udp_handler_ = std::make_unique<UdpHandler>(config_);
    }
    else if (config_.protocol == "dns") {
        dns_handler_ = std::make_unique<DnsHandler>(config_);
    }
    else {
        // Default to ICMP (legacy BlackNurse)
        attack_engine_ = std::make_unique<AttackEngine>(config_);
    }
    
    Logger::info("Framework Core initialized for protocol: " + config_.protocol);
}

FrameworkCore::~FrameworkCore() {
    shutdown();
}

bool FrameworkCore::initialize() {
    try {
        Logger::info("Initializing BlackNurse 3.0 Framework...");
        
        // Initialize the appropriate protocol handler
        if (http_handler_) {
            return http_handler_->initialize();
        }
        else if (tcp_handler_) {
            return tcp_handler_->initialize();
        }
        else if (udp_handler_) {
            return udp_handler_->initialize();
        }
        else if (dns_handler_) {
            return dns_handler_->initialize();
        }
        else if (attack_engine_) {
            // Legacy ICMP initialization
            return true;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        Logger::error("Framework initialization failed: " + std::string(e.what()));
        return false;
    }
}

bool FrameworkCore::start_attack() {
    if (running_) {
        Logger::warning("Framework is already running");
        return false;
    }
    
    try {
        running_ = true;
        start_time_ = std::chrono::steady_clock::now();
        
        Logger::info("Starting multi-protocol attack...");
        
        // Start the appropriate protocol handler
        if (http_handler_) {
            return http_handler_->start_attack();
        }
        else if (tcp_handler_) {
            return tcp_handler_->start_attack();
        }
        else if (udp_handler_) {
            return udp_handler_->start_attack();
        }
        else if (dns_handler_) {
            return dns_handler_->start_attack();
        }
        else if (attack_engine_) {
            attack_engine_->start();
            return true;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        Logger::error("Failed to start attack: " + std::string(e.what()));
        running_ = false;
        return false;
    }
}

void FrameworkCore::stop_attack() {
    if (!running_) {
        return;
    }
    
    Logger::info("Stopping attack...");
    running_ = false;
    
    // Stop the appropriate protocol handler
    if (http_handler_) {
        http_handler_->stop_attack();
    }
    else if (tcp_handler_) {
        tcp_handler_->stop_attack();
    }
    else if (udp_handler_) {
        udp_handler_->stop_attack();
    }
    else if (dns_handler_) {
        dns_handler_->stop_attack();
    }
    else if (attack_engine_) {
        attack_engine_->stop();
    }
}

void FrameworkCore::shutdown() {
    stop_attack();
    
    // Cleanup protocol handlers
    http_handler_.reset();
    tcp_handler_.reset();
    udp_handler_.reset();
    dns_handler_.reset();
    attack_engine_.reset();
    
    Logger::info("Framework shutdown complete");
}

AttackStats FrameworkCore::get_stats() const {
    if (http_handler_) {
        return http_handler_->get_stats();
    }
    else if (tcp_handler_) {
        return tcp_handler_->get_stats();
    }
    else if (udp_handler_) {
        return udp_handler_->get_stats();
    }
    else if (dns_handler_) {
        return dns_handler_->get_stats();
    }
    else if (attack_engine_) {
        return attack_engine_->get_stats();
    }
    
    return stats_;
}

bool FrameworkCore::is_running() const {
    return running_;
}

std::string FrameworkCore::get_protocol() const {
    return config_.protocol;
}

std::chrono::seconds FrameworkCore::get_uptime() const {
    if (!running_) {
        return std::chrono::seconds(0);
    }
    
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
}

void FrameworkCore::update_config(const blacknurse::Config& new_config) {
    if (running_) {
        Logger::warning("Cannot update configuration while framework is running");
        return;
    }
    
    config_ = new_config;
    Logger::info("Configuration updated");
}

} // namespace BlackNurse