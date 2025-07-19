#include "../common/config.hpp"
#include "../common/logger.hpp"
#include <iostream>

using namespace blacknurse;

int main() {
    std::cout << "BlackNurse 3.0 Framework Test\n";
    
    Config config;
    config.target_ip = "127.0.0.1";
    config.protocol = "http";
    config.threads = 2;
    config.rate_limit = 100;
    
    if (config.validate()) {
        std::cout << "Configuration is valid\n";
        std::cout << "Target: " << config.target_ip << "\n";
        std::cout << "Protocol: " << config.protocol << "\n";
        std::cout << "Threads: " << config.threads << "\n";
        std::cout << "Rate: " << config.rate_limit << " pps\n";
    } else {
        std::cout << "Configuration is invalid\n";
    }
    
    AttackStats stats;
    stats.packets_sent = 1000;
    stats.packets_failed = 10;
    stats.bytes_sent = 50000;
    
    std::cout << "\nTest Statistics:\n";
    std::cout << "Packets sent: " << stats.packets_sent.load() << "\n";
    std::cout << "Packets failed: " << stats.packets_failed.load() << "\n";
    std::cout << "Bytes sent: " << stats.bytes_sent.load() << "\n";
    
    Logger::info("Framework test completed successfully");
    
    return 0;
}