te# 🔥 BlackNurse 2.0 -DoS Testing Tool

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/blacknurse/blacknurse)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)]()
[![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)]()
[![CUDA](https://img.shields.io/badge/CUDA-Optional-orange.svg)]()

BlackNurse 2.0 is a completely rewritten, modern implementation of the famous BlackNurse ICMP DoS attack. This  edition features cutting-edge technologies including multi-threading, GPU acceleration, real-time monitoring, and evasion techniques.

## 🚀 What's New in 2.0

- **🔥 Modern C++20 Implementation** - Complete rewrite with modern standards
- **⚡ Multi-threaded Architecture** - Utilizes all CPU cores for maximum performance
- **🎮 GPU Acceleration** - Optional CUDA support for extreme packet rates
- **📊 Real-time Monitoring** - Beautiful console interface with live statistics
- **🥷 Stealth Mode** - Evasion techniques to bypass detection
- **🧠 Adaptive Rate Control** - Intelligent rate adjustment based on system feedback
- **🔧 CMake Build System** - Modern, cross-platform build configuration
- **📈 Performance Analytics** - Detailed system resource monitoring

## 📋 Features

### Core Capabilities
- **High-Performance Packet Generation** - Up to millions of packets per second
- **Multiple Attack Vectors** - ICMP, fragmented packets, stealth modes
- **Intelligent Rate Limiting** - Prevents system overload and detection
- **Cross-Platform Support** - Linux and macOS compatible
- **Memory Efficient** - Optimized memory usage with connection pooling

### Enhanced Features
- **GPU Acceleration** - CUDA-powered packet generation (optional)
- **Stealth Techniques** - Random source IPs, TTL variation, payload randomization
- **Fragmentation Support** - Packet fragmentation for enhanced evasion
- **Real-time Statistics** - Live performance monitoring with graphs
- **Adaptive Control** - Dynamic rate adjustment based on error rates
- **Signal Handling** - Graceful shutdown with statistics summary

## 🎯 Target Compatibility

BlackNurse 2.0 is effective against the same targets as the original, plus many more:

### Confirmed Vulnerable Devices
- **Cisco ASA Series** - 5505, 5506, 5515, 5525, 5540, 5550, 5515-X
- **Cisco Routers** - 6500 series with SUP2T, 897 series
- **Fortinet FortiGate** - v5.4.1+, 60c, 100D series
- **Palo Alto** - 5050 Firewalls (firmware 7.1.4-h2)
- **SonicWall** - Various models (configurable mitigation)
- **Zyxel** - NWA3560-N, Zywall USG50
- **And many more...**

### Impact
- **CPU Exhaustion** - 100% CPU load on vulnerable devices
- **Service Disruption** - DoS condition with low bandwidth requirements
- **Resource Starvation** - Memory and connection table exhaustion

## 🛠️ Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential cmake git
sudo apt install libssl-dev # Optional: for enhanced features

# macOS
brew install cmake
xcode-select --install
```

### Optional: CUDA Support

```bash
# Install NVIDIA CUDA Toolkit (for GPU acceleration)
# Visit: https://developer.nvidia.com/cuda-downloads
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/yigitnosql/blacknurse.git
cd blacknurse

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
make -j$(nproc)

# Install (optional)
sudo make install
```

### Quick Build (Legacy)

```bash
# Simple build with make
make
```

## 🚀 Usage

### Basic Usage

```bash
# Simple attack
sudo ./blacknurse 192.168.1.1

# High-intensity attack with 8 threads
sudo ./blacknurse -t 8 -r 5000 192.168.1.1

# Stealth mode with adaptive rate control
sudo ./blacknurse --stealth --adaptive -r 2000 192.168.1.1
```

### Enhanced Usage

```bash
# GPU-accelerated attack (if CUDA available)
sudo ./blacknurse --gpu -r 50000 -t 16 192.168.1.1

# Time-limited attack with custom payload
sudo ./blacknurse -d 60 -p 64 -r 3000 192.168.1.1

# Stealth attack with custom source IP
sudo ./blacknurse --stealth -s 10.0.0.100 -r 1000 192.168.1.1
```

### Command Line Options

```
Usage: blacknurse [OPTIONS] <target_ip>

Options:
  -h, --help              Show help message
  -v, --verbose           Enable verbose logging
  -t, --threads <num>     Number of threads (default: CPU cores)
  -r, --rate <pps>        Packets per second (default: 1000)
  -d, --duration <sec>    Attack duration in seconds (default: unlimited)
  -p, --payload <size>    Payload size in bytes (default: 32)
  -s, --source <ip>       Source IP address (default: random)
  --gpu                   Enable GPU acceleration (if available)
  --stealth               Enable stealth mode
  --adaptive              Enable adaptive rate control
  --stats-interval <sec>  Statistics update interval (default: 1)
```

## 📊 Performance

### Benchmarks (Intel i9-12900K, RTX 4090)

| Mode | Threads | Rate (pps) | CPU Usage | Memory |
|------|---------|------------|-----------|--------|
| Standard | 16 | 100,000 | 45% | 50MB |
| GPU Accelerated | 16 | 500,000 | 25% | 200MB |
| Stealth | 8 | 50,000 | 30% | 40MB |

### System Requirements

- **Minimum**: 2 CPU cores, 1GB RAM
- **Recommended**: 8+ CPU cores, 4GB RAM
- **GPU Mode**: NVIDIA GPU with CUDA 11.0+
- **Privileges**: Root access or CAP_NET_RAW capability

## 🔒 Security & Ethics

### ⚠️ Important Disclaimers

- **Educational Purpose Only** - This tool is for learning and authorized testing
- **Legal Compliance** - Only use against systems you own or have explicit permission to test
- **Responsible Disclosure** - Report vulnerabilities through proper channels
- **No Warranty** - Use at your own risk

### Ethical Guidelines

1. **Authorization Required** - Never test without explicit permission
2. **Responsible Testing** - Use minimal necessary force
3. **Documentation** - Keep detailed logs of testing activities
4. **Disclosure** - Report findings to appropriate parties
5. **Legal Compliance** - Follow all applicable laws and regulations

## 🛡️ Detection & Mitigation

### Detection Methods
- **Traffic Analysis** - Monitor for high-rate ICMP type 3 packets
- **Rate Limiting** - Implement ICMP rate limits
- **Pattern Recognition** - Detect packet patterns and signatures
- **Behavioral Analysis** - Monitor CPU usage spikes

### Mitigation Strategies
- **ICMP Rate Limiting** - Limit ICMP packets per second
- **Firewall Rules** - Block or rate-limit ICMP type 3
- **DDoS Protection** - Deploy anti-DDoS solutions
- **Firmware Updates** - Keep network devices updated

## 🔧 Development

### Building with Debug Info

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### Running Tests

```bash
# Run built-in tests
./blacknurse --help
./blacknurse --version
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📚 Technical Details

### Architecture
- **Multi-threaded Design** - Worker threads for packet generation
- **Lock-free Programming** - Atomic operations for performance
- **Memory Pool** - Efficient memory management
- **CUDA Integration** - GPU kernels for packet processing

### Packet Structure
- **IP Header** - Standard IPv4 header with customizable fields
- **ICMP Header** - Type 3 (Destination Unreachable) packets
- **Payload** - Configurable size with pattern or random data
- **Checksums** - Proper IP and ICMP checksum calculation

## 📖 References

- [Original BlackNurse Research](http://www.blacknurse.dk)
- [ICMP RFC 792](https://tools.ietf.org/html/rfc792)
- [Vendor Security Advisories](#vendor-responses)

### Vendor Responses
- [Checkpoint Security Advisory](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk114500)
- [Fortinet Blog Post](https://blog.fortinet.com/2016/11/14/black-nurse-ddos-attack-power-of-granular-packet-inspection-of-fortiddos-with-unpredictable-ddos-attacks)
- [Palo Alto Research](http://researchcenter.paloaltonetworks.com/2016/11/note-customers-regarding-blacknurse-report/)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original BlackNurse researchers
- Security community contributors
- Open source libraries used

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
