/**
 * BlackNurse 2.0 - CUDA GPU Accelerator
 * 
 * GPU-accelerated packet generation and processing for extreme performance.
 * Utilizes CUDA for parallel packet crafting and checksum calculations.
 */

#pragma once

#include <vector>
#include <memory>
#include <atomic>
#include <mutex>

#include "common/config.hpp"
#include "common/logger.hpp"
#include "network/packet_generator.hpp"

#ifdef CUDA_ENABLED
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#endif

namespace blacknurse {

/**
 * GPU memory buffer for efficient packet processing
 */
struct GpuBuffer {
    void* device_ptr = nullptr;
    void* host_ptr = nullptr;
    size_t size = 0;
    bool allocated = false;
    
    ~GpuBuffer() {
#ifdef CUDA_ENABLED
        if (allocated && device_ptr) {
            cudaFree(device_ptr);
        }
        if (host_ptr) {
            cudaFreeHost(host_ptr);
        }
#endif
    }
};

/**
 * CUDA-accelerated packet generator
 */
class CudaAccelerator {
public:
    static bool is_available() {
#ifdef CUDA_ENABLED
        int device_count = 0;
        cudaError_t error = cudaGetDeviceCount(&device_count);
        return (error == cudaSuccess && device_count > 0);
#else
        return false;
#endif
    }
    
    explicit CudaAccelerator(const Config& config) 
        : config_(config), initialized_(false), device_id_(0) {
#ifdef CUDA_ENABLED
        initialize();
#else
        throw std::runtime_error("CUDA support not compiled");
#endif
    }
    
    ~CudaAccelerator() {
#ifdef CUDA_ENABLED
        cleanup();
#endif
    }
    
    /**
     * Generate packets in parallel on GPU
     */
    std::vector<Packet> generate_packet_batch(size_t batch_size) {
#ifdef CUDA_ENABLED
        if (!initialized_) {
            throw std::runtime_error("CUDA accelerator not initialized");
        }
        
        std::vector<Packet> packets;
        packets.reserve(batch_size);
        
        // Calculate packet size
        size_t packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + config_.payload_size;
        size_t total_size = batch_size * packet_size;
        
        // Allocate GPU memory if needed
        if (packet_buffer_.size < total_size) {
            reallocate_buffer(total_size);
        }
        
        // Launch CUDA kernel for packet generation
        dim3 block_size(256);
        dim3 grid_size((batch_size + block_size.x - 1) / block_size.x);
        
        generate_packets_kernel<<<grid_size, block_size>>>(
            static_cast<uint8_t*>(packet_buffer_.device_ptr),
            batch_size,
            packet_size,
            config_.target_ip.c_str(),
            config_.icmp_type,
            config_.icmp_code,
            config_.payload_size
        );
        
        // Check for kernel launch errors
        cudaError_t error = cudaGetLastError();
        if (error != cudaSuccess) {
            Logger::error("CUDA kernel launch failed: " + std::string(cudaGetErrorString(error)));
            return packets;
        }
        
        // Wait for kernel completion
        cudaDeviceSynchronize();
        
        // Copy results back to host
        error = cudaMemcpy(packet_buffer_.host_ptr, packet_buffer_.device_ptr, 
                          total_size, cudaMemcpyDeviceToHost);
        if (error != cudaSuccess) {
            Logger::error("CUDA memory copy failed: " + std::string(cudaGetErrorString(error)));
            return packets;
        }
        
        // Convert to packet objects
        uint8_t* host_data = static_cast<uint8_t*>(packet_buffer_.host_ptr);
        for (size_t i = 0; i < batch_size; ++i) {
            Packet packet;
            packet.data.resize(packet_size);
            std::memcpy(packet.data.data(), host_data + i * packet_size, packet_size);
            packets.push_back(std::move(packet));
        }
        
        return packets;
#else
        (void)batch_size;
        return {};
#endif
    }
    
    /**
     * Calculate checksums in parallel on GPU
     */
    void calculate_checksums_batch(std::vector<Packet>& packets) {
#ifdef CUDA_ENABLED
        if (!initialized_ || packets.empty()) {
            return;
        }
        
        size_t batch_size = packets.size();
        size_t packet_size = packets[0].size();
        size_t total_size = batch_size * packet_size;
        
        // Ensure buffer is large enough
        if (checksum_buffer_.size < total_size) {
            reallocate_checksum_buffer(total_size);
        }
        
        // Copy packets to GPU
        uint8_t* host_data = static_cast<uint8_t*>(checksum_buffer_.host_ptr);
        for (size_t i = 0; i < batch_size; ++i) {
            std::memcpy(host_data + i * packet_size, packets[i].raw(), packet_size);
        }
        
        cudaError_t error = cudaMemcpy(checksum_buffer_.device_ptr, checksum_buffer_.host_ptr,
                                      total_size, cudaMemcpyHostToDevice);
        if (error != cudaSuccess) {
            Logger::error("CUDA memory copy to device failed: " + std::string(cudaGetErrorString(error)));
            return;
        }
        
        // Launch checksum calculation kernel
        dim3 block_size(256);
        dim3 grid_size((batch_size + block_size.x - 1) / block_size.x);
        
        calculate_checksums_kernel<<<grid_size, block_size>>>(
            static_cast<uint8_t*>(checksum_buffer_.device_ptr),
            batch_size,
            packet_size
        );
        
        // Check for errors
        error = cudaGetLastError();
        if (error != cudaSuccess) {
            Logger::error("CUDA checksum kernel failed: " + std::string(cudaGetErrorString(error)));
            return;
        }
        
        cudaDeviceSynchronize();
        
        // Copy results back
        error = cudaMemcpy(checksum_buffer_.host_ptr, checksum_buffer_.device_ptr,
                          total_size, cudaMemcpyDeviceToHost);
        if (error != cudaSuccess) {
            Logger::error("CUDA memory copy from device failed: " + std::string(cudaGetErrorString(error)));
            return;
        }
        
        // Update packet data
        for (size_t i = 0; i < batch_size; ++i) {
            std::memcpy(packets[i].raw(), host_data + i * packet_size, packet_size);
        }
#else
        (void)packets;
#endif
    }
    
    /**
     * Get GPU device information
     */
    struct GpuInfo {
        std::string name;
        size_t total_memory = 0;
        size_t free_memory = 0;
        int compute_capability_major = 0;
        int compute_capability_minor = 0;
        int multiprocessor_count = 0;
        int max_threads_per_block = 0;
    };
    
    GpuInfo get_device_info() const {
        GpuInfo info;
        
#ifdef CUDA_ENABLED
        if (!initialized_) {
            return info;
        }
        
        cudaDeviceProp prop;
        cudaError_t error = cudaGetDeviceProperties(&prop, device_id_);
        if (error == cudaSuccess) {
            info.name = prop.name;
            info.total_memory = prop.totalGlobalMem;
            info.compute_capability_major = prop.major;
            info.compute_capability_minor = prop.minor;
            info.multiprocessor_count = prop.multiProcessorCount;
            info.max_threads_per_block = prop.maxThreadsPerBlock;
            
            size_t free_mem, total_mem;
            cudaMemGetInfo(&free_mem, &total_mem);
            info.free_memory = free_mem;
        }
#endif
        
        return info;
    }
    
private:
#ifdef CUDA_ENABLED
    void initialize() {
        // Get device count
        int device_count = 0;
        cudaError_t error = cudaGetDeviceCount(&device_count);
        if (error != cudaSuccess || device_count == 0) {
            throw std::runtime_error("No CUDA devices available");
        }
        
        // Select best device
        device_id_ = select_best_device();
        
        // Set device
        error = cudaSetDevice(device_id_);
        if (error != cudaSuccess) {
            throw std::runtime_error("Failed to set CUDA device: " + std::string(cudaGetErrorString(error)));
        }
        
        // Get device properties
        auto info = get_device_info();
        Logger::info("CUDA device initialized: " + info.name);
        Logger::info("Total GPU memory: " + std::to_string(info.total_memory / (1024*1024)) + " MB");
        Logger::info("Compute capability: " + std::to_string(info.compute_capability_major) + 
                    "." + std::to_string(info.compute_capability_minor));
        
        initialized_ = true;
    }
    
    int select_best_device() {
        int device_count = 0;
        cudaGetDeviceCount(&device_count);
        
        int best_device = 0;
        size_t max_memory = 0;
        
        for (int i = 0; i < device_count; ++i) {
            cudaDeviceProp prop;
            cudaGetDeviceProperties(&prop, i);
            
            if (prop.totalGlobalMem > max_memory) {
                max_memory = prop.totalGlobalMem;
                best_device = i;
            }
        }
        
        return best_device;
    }
    
    void reallocate_buffer(size_t new_size) {
        cleanup_buffer(packet_buffer_);
        
        // Allocate device memory
        cudaError_t error = cudaMalloc(&packet_buffer_.device_ptr, new_size);
        if (error != cudaSuccess) {
            throw std::runtime_error("Failed to allocate GPU memory: " + std::string(cudaGetErrorString(error)));
        }
        
        // Allocate pinned host memory for faster transfers
        error = cudaMallocHost(&packet_buffer_.host_ptr, new_size);
        if (error != cudaSuccess) {
            cudaFree(packet_buffer_.device_ptr);
            throw std::runtime_error("Failed to allocate pinned host memory: " + std::string(cudaGetErrorString(error)));
        }
        
        packet_buffer_.size = new_size;
        packet_buffer_.allocated = true;
    }
    
    void reallocate_checksum_buffer(size_t new_size) {
        cleanup_buffer(checksum_buffer_);
        
        cudaError_t error = cudaMalloc(&checksum_buffer_.device_ptr, new_size);
        if (error != cudaSuccess) {
            throw std::runtime_error("Failed to allocate GPU checksum memory: " + std::string(cudaGetErrorString(error)));
        }
        
        error = cudaMallocHost(&checksum_buffer_.host_ptr, new_size);
        if (error != cudaSuccess) {
            cudaFree(checksum_buffer_.device_ptr);
            throw std::runtime_error("Failed to allocate pinned checksum memory: " + std::string(cudaGetErrorString(error)));
        }
        
        checksum_buffer_.size = new_size;
        checksum_buffer_.allocated = true;
    }
    
    void cleanup_buffer(GpuBuffer& buffer) {
        if (buffer.allocated) {
            if (buffer.device_ptr) {
                cudaFree(buffer.device_ptr);
                buffer.device_ptr = nullptr;
            }
            if (buffer.host_ptr) {
                cudaFreeHost(buffer.host_ptr);
                buffer.host_ptr = nullptr;
            }
            buffer.allocated = false;
            buffer.size = 0;
        }
    }
    
    void cleanup() {
        if (initialized_) {
            cleanup_buffer(packet_buffer_);
            cleanup_buffer(checksum_buffer_);
            cudaDeviceReset();
            initialized_ = false;
        }
    }
#endif
    
    const Config& config_;
    bool initialized_;
    int device_id_;
    
    GpuBuffer packet_buffer_;
    GpuBuffer checksum_buffer_;
};

#ifdef CUDA_ENABLED
// CUDA kernel declarations
__global__ void generate_packets_kernel(uint8_t* packets, size_t batch_size, size_t packet_size,
                                       const char* target_ip, uint8_t icmp_type, uint8_t icmp_code,
                                       size_t payload_size);

__global__ void calculate_checksums_kernel(uint8_t* packets, size_t batch_size, size_t packet_size);
#endif

} // namespace blacknurse