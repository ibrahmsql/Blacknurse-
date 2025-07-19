/**
 * BlackNurse 2.0 - Logging System
 * 
 * Thread-safe, high-performance logging with multiple levels and formatting
 */

#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <memory>

namespace blacknurse {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

class Logger {
public:
    static void init(LogLevel level = LogLevel::INFO, const std::string& filename = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        current_level_ = level;
        
        if (!filename.empty()) {
            file_stream_ = std::make_unique<std::ofstream>(filename, std::ios::app);
            if (!file_stream_->is_open()) {
                std::cerr << "Warning: Could not open log file: " << filename << std::endl;
                file_stream_.reset();
            }
        }
    }
    
    static void debug(const std::string& message) {
        log(LogLevel::DEBUG, message);
    }
    
    static void info(const std::string& message) {
        log(LogLevel::INFO, message);
    }
    
    static void warning(const std::string& message) {
        log(LogLevel::WARNING, message);
    }
    
    static void error(const std::string& message) {
        log(LogLevel::ERROR, message);
    }
    
    static void critical(const std::string& message) {
        log(LogLevel::CRITICAL, message);
    }
    
    static void set_level(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        current_level_ = level;
    }
    
private:
    static void log(LogLevel level, const std::string& message) {
        if (level < current_level_) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
           << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";
        
        // Add color codes for console output
        std::string color_code;
        std::string reset_code = "\033[0m";
        
        switch (level) {
            case LogLevel::DEBUG:
                ss << "[🔍 DEBUG] ";
                color_code = "\033[36m"; // Cyan
                break;
            case LogLevel::INFO:
                ss << "[ℹ️  INFO ] ";
                color_code = "\033[32m"; // Green
                break;
            case LogLevel::WARNING:
                ss << "[⚠️  WARN ] ";
                color_code = "\033[33m"; // Yellow
                break;
            case LogLevel::ERROR:
                ss << "[❌ ERROR] ";
                color_code = "\033[31m"; // Red
                break;
            case LogLevel::CRITICAL:
                ss << "[💥 CRIT ] ";
                color_code = "\033[35m"; // Magenta
                break;
        }
        
        std::string log_line = ss.str() + message;
        
        // Output to console with colors
        std::cout << color_code << log_line << reset_code << std::endl;
        
        // Output to file without colors
        if (file_stream_ && file_stream_->is_open()) {
            *file_stream_ << log_line << std::endl;
            file_stream_->flush();
        }
    }
    
    static std::mutex mutex_;
    static LogLevel current_level_;
    static std::unique_ptr<std::ofstream> file_stream_;
};

// Static member definitions
std::mutex Logger::mutex_;
LogLevel Logger::current_level_ = LogLevel::INFO;
std::unique_ptr<std::ofstream> Logger::file_stream_;

} // namespace blacknurse