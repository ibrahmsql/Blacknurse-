/**
 * BlackNurse Framework  - WAF Bypass Engine
 * 
 * Web Application Firewall bypass techniques including
 * encoding, obfuscation, fragmentation, and modern evasion methods
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <random>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>

#include "../framework/framework_core.hpp"
#include "../common/config.hpp"
#include "../common/logger.hpp"

namespace BlackNurse {

/**
 * WAF Types
 */
enum class WafType {
    UNKNOWN,
    CLOUDFLARE,
    AWS_WAF,
    AZURE_WAF,
    AKAMAI,
    IMPERVA,
    F5_BIG_IP,
    BARRACUDA,
    FORTINET,
    SUCURI,
    MODSECURITY,
    NAXSI,
    COMODO,
    WORDFENCE,
    WALLARM,
    RADWARE,
    CITRIX_NETSCALER,
    PALO_ALTO,
    CHECKPOINT,
    SOPHOS,
    CUSTOM
};

/**
 * Encoding Methods
 */
enum class EncodingMethod {
    URL_ENCODING,
    DOUBLE_URL_ENCODING,
    UNICODE_ENCODING,
    HTML_ENTITY_ENCODING,
    HEX_ENCODING,
    BASE64_ENCODING,
    UTF8_ENCODING,
    UTF16_ENCODING,
    UTF32_ENCODING,
    MIXED_CASE_ENCODING,
    COMMENT_INSERTION,
    WHITESPACE_MANIPULATION,
    PARAMETER_POLLUTION,
    CHUNKED_ENCODING,
    GZIP_COMPRESSION,
    DEFLATE_COMPRESSION
};

/**
 * Bypass Techniques
 */
enum class BypassTechnique {
    CASE_VARIATION,
    COMMENT_INSERTION,
    WHITESPACE_MANIPULATION,
    PARAMETER_POLLUTION,
    HTTP_VERB_TAMPERING,
    CONTENT_TYPE_MANIPULATION,
    HEADER_INJECTION,
    PATH_TRAVERSAL_ENCODING,
    SQL_COMMENT_INSERTION,
    XSS_FILTER_BYPASS,
    COMMAND_INJECTION_BYPASS,
    FILE_INCLUSION_BYPASS,
    XXSS_BYPASS,
    CSRF_BYPASS,
    RATE_LIMIT_BYPASS,
    IP_ROTATION,
    USER_AGENT_ROTATION,
    REFERER_SPOOFING,
    COOKIE_MANIPULATION,
    SESSION_FIXATION
};

/**
 * WAF Detection Result
 */
struct WafDetectionResult {
    bool detected = false;
    WafType type = WafType::UNKNOWN;
    std::string vendor;
    std::string version;
    double confidence = 0.0;
    std::vector<std::string> signatures;
    std::vector<std::string> headers;
    std::vector<std::string> response_patterns;
    std::unordered_map<std::string, std::string> fingerprints;
};

/**
 * Bypass Test Result
 */
struct BypassTestResult {
    bool successful = false;
    std::string technique_used;
    std::string payload_used;
    int response_code = 0;
    std::string response_body;
    std::chrono::milliseconds response_time{0};
    bool blocked = false;
    std::string block_reason;
    double success_probability = 0.0;
};

/**
 * Payload Template
 */
struct PayloadTemplate {
    std::string name;
    std::string category;
    std::string base_payload;
    std::vector<EncodingMethod> applicable_encodings;
    std::vector<BypassTechnique> applicable_techniques;
    std::string description;
    int severity_level = 1; // 1-10
    bool requires_context = false;
};

/**
 * WAF Bypass Configuration
 */
struct WafBypassConfig {
    std::vector<EncodingMethod> enabled_encodings;
    std::vector<BypassTechnique> enabled_techniques;
    bool auto_detect_waf = true;
    bool adaptive_bypass = true;
    uint32_t max_bypass_attempts = 100;
    std::chrono::milliseconds test_delay{500};
    bool use_machine_learning = true;
    bool save_successful_bypasses = true;
    std::string bypass_database_path;
    
    // Rate limiting
    uint32_t max_requests_per_minute = 60;
    bool respect_rate_limits = true;
    
    // Stealth options
    bool randomize_user_agents = true;
    bool use_proxy_rotation = true;
    std::vector<std::string> proxy_list;
    bool simulate_human_behavior = true;
    
    // Enhanced options
    bool use_distributed_testing = false;
    std::vector<std::string> distributed_nodes;
    bool enable_payload_mutation = true;
    double mutation_rate = 0.1;
};

/**
 * WAF Bypass Engine Implementation
 */
class WafBypassEngine {
public:
    WafBypassEngine();
    ~WafBypassEngine();
    
    // Initialization
    bool initialize(const WafBypassConfig& config);
    void shutdown();
    
    // WAF Detection
    WafDetectionResult detect_waf(const Target& target);
    bool is_waf_present(const Target& target);
    WafType identify_waf_type(const std::string& response_headers, const std::string& response_body);
    
    // Bypass Testing
    std::vector<BypassTestResult> test_bypass_techniques(const Target& target, const std::string& payload);
    BypassTestResult test_single_bypass(const Target& target, const std::string& payload, BypassTechnique technique);
    std::vector<std::string> generate_bypass_payloads(const std::string& original_payload, WafType waf_type = WafType::UNKNOWN);
    
    // Encoding Methods
    std::string apply_encoding(const std::string& payload, EncodingMethod method);
    std::string apply_multiple_encodings(const std::string& payload, const std::vector<EncodingMethod>& methods);
    std::string decode_payload(const std::string& encoded_payload, EncodingMethod method);
    
    // Bypass Techniques
    std::string apply_bypass_technique(const std::string& payload, BypassTechnique technique);
    std::string apply_case_variation(const std::string& payload);
    std::string insert_comments(const std::string& payload, const std::string& comment_style = "/**/");
    std::string manipulate_whitespace(const std::string& payload);
    std::vector<std::string> create_parameter_pollution(const std::unordered_map<std::string, std::string>& params);
    
    // Enhanced Bypass Methods
    std::string apply_sql_injection_bypass(const std::string& payload, WafType waf_type);
    std::string apply_xss_bypass(const std::string& payload, WafType waf_type);
    std::string apply_command_injection_bypass(const std::string& payload, WafType waf_type);
    std::string apply_path_traversal_bypass(const std::string& payload, WafType waf_type);
    std::string apply_file_inclusion_bypass(const std::string& payload, WafType waf_type);
    
    // Machine Learning Integration
    bool train_bypass_model(const std::vector<BypassTestResult>& training_data);
    std::vector<std::string> predict_successful_bypasses(const std::string& payload, WafType waf_type);
    double calculate_bypass_probability(const std::string& payload, BypassTechnique technique, WafType waf_type);
    
    // Payload Management
    bool load_payload_templates(const std::string& templates_file);
    bool save_payload_templates(const std::string& templates_file);
    std::vector<PayloadTemplate> get_payloads_by_category(const std::string& category);
    PayloadTemplate generate_custom_payload(const std::string& base, const std::string& category);
    
    // Statistics and Reporting
    std::unordered_map<std::string, uint64_t> get_bypass_statistics();
    std::vector<std::string> get_most_successful_techniques(WafType waf_type);
    void export_bypass_report(const std::string& filename);
    
private:
    // Core components
    WafBypassConfig config_;
    std::atomic<bool> initialized_{false};
    
    // WAF Detection Engine
    class WafDetector {
    public:
        WafDetectionResult detect(const Target& target);
        WafType identify_by_headers(const std::unordered_map<std::string, std::string>& headers);
        WafType identify_by_response(const std::string& response_body);
        WafType identify_by_behavior(const Target& target);
        
    private:
        std::unordered_map<WafType, std::vector<std::regex>> header_signatures_;
        std::unordered_map<WafType, std::vector<std::regex>> response_signatures_;
        std::unordered_map<WafType, std::vector<std::string>> behavior_tests_;
        
        void initialize_signatures();
        double calculate_confidence(const std::vector<bool>& matches);
    };
    
    std::unique_ptr<WafDetector> detector_;
    
    // Encoding Engine
    class EncodingEngine {
    public:
        std::string url_encode(const std::string& input, bool double_encode = false);
        std::string unicode_encode(const std::string& input);
        std::string html_entity_encode(const std::string& input);
        std::string hex_encode(const std::string& input);
        std::string base64_encode(const std::string& input);
        std::string utf8_encode(const std::string& input);
        std::string utf16_encode(const std::string& input);
        std::string utf32_encode(const std::string& input);
        
        // Enhanced encoding
        std::string mixed_case_encode(const std::string& input);
        std::string chunked_encode(const std::string& input);
        std::string compress_gzip(const std::string& input);
        std::string compress_deflate(const std::string& input);
        
    private:
        std::random_device rd_;
        std::mt19937 gen_;
    };
    
    std::unique_ptr<EncodingEngine> encoder_;
    
    // Payload Mutation Engine
    class PayloadMutator {
    public:
        std::vector<std::string> mutate_payload(const std::string& payload, double mutation_rate);
        std::string apply_genetic_algorithm(const std::string& payload, const std::function<double(const std::string&)>& fitness_func);
        std::string crossover_payloads(const std::string& payload1, const std::string& payload2);
        std::string mutate_single_payload(const std::string& payload);
        
    private:
        std::random_device rd_;
        std::mt19937 gen_;
        std::uniform_real_distribution<> mutation_dist_;
        
        std::string random_character_substitution(const std::string& payload);
        std::string random_insertion(const std::string& payload);
        std::string random_deletion(const std::string& payload);
    };
    
    std::unique_ptr<PayloadMutator> mutator_;
    
    // Bypass Database
    class BypassDatabase {
    public:
        bool load_from_file(const std::string& filename);
        bool save_to_file(const std::string& filename);
        void add_successful_bypass(const std::string& payload, BypassTechnique technique, WafType waf_type);
        std::vector<std::string> get_successful_bypasses(WafType waf_type, const std::string& category = "");
        double get_success_rate(BypassTechnique technique, WafType waf_type);
        
    private:
        struct BypassRecord {
            std::string payload;
            BypassTechnique technique;
            WafType waf_type;
            std::string category;
            std::chrono::system_clock::time_point timestamp;
            uint32_t success_count = 0;
            uint32_t total_attempts = 0;
        };
        
        std::vector<BypassRecord> records_;
        std::mutex database_mutex_;
    };
    
    std::unique_ptr<BypassDatabase> database_;
    
    // Payload Templates
    std::vector<PayloadTemplate> payload_templates_;
    std::unordered_map<std::string, std::vector<PayloadTemplate>> templates_by_category_;
    
    // WAF-specific bypass strategies
    std::unordered_map<WafType, std::vector<BypassTechnique>> waf_specific_techniques_;
    std::unordered_map<WafType, std::vector<EncodingMethod>> waf_specific_encodings_;
    
    // Statistics
    std::unordered_map<std::string, uint64_t> technique_success_count_;
    std::unordered_map<std::string, uint64_t> technique_attempt_count_;
    std::mutex stats_mutex_;
    
    // Random generators
    std::random_device rd_;
    std::mt19937 gen_;
    
    // Utility methods
    void initialize_payload_templates();
    void initialize_waf_strategies();
    void load_default_payloads();
    
    // WAF-specific bypass implementations
    std::string bypass_cloudflare(const std::string& payload);
    std::string bypass_aws_waf(const std::string& payload);
    std::string bypass_azure_waf(const std::string& payload);
    std::string bypass_akamai(const std::string& payload);
    std::string bypass_imperva(const std::string& payload);
    std::string bypass_f5_big_ip(const std::string& payload);
    std::string bypass_modsecurity(const std::string& payload);
    
    // HTTP manipulation
    std::unordered_map<std::string, std::string> create_bypass_headers(BypassTechnique technique);
    std::string manipulate_http_method(const std::string& original_method, BypassTechnique technique);
    std::string manipulate_content_type(const std::string& original_type, BypassTechnique technique);
    
    // Context-aware bypasses
    std::string apply_context_aware_bypass(const std::string& payload, const std::string& context);
    bool is_sql_context(const std::string& context);
    bool is_xss_context(const std::string& context);
    bool is_command_context(const std::string& context);
    
    // Rate limiting and stealth
    std::chrono::steady_clock::time_point last_request_time_;
    std::mutex rate_limit_mutex_;
    void enforce_rate_limit();
    std::string get_random_user_agent();
    std::string get_random_referer();
    
    // Logging and debugging
    void log_bypass_attempt(const std::string& payload, BypassTechnique technique, bool success);
    void log_waf_detection(const WafDetectionResult& result);
    void update_statistics(BypassTechnique technique, bool success);
};

/**
 * WAF Utility Functions
 */
namespace WafUtils {
    std::string waf_type_to_string(WafType type);
    WafType string_to_waf_type(const std::string& type_str);
    std::string encoding_method_to_string(EncodingMethod method);
    EncodingMethod string_to_encoding_method(const std::string& method_str);
    std::string bypass_technique_to_string(BypassTechnique technique);
    BypassTechnique string_to_bypass_technique(const std::string& technique_str);
    
    bool is_blocked_response(int status_code, const std::string& response_body);
    bool contains_waf_signature(const std::string& text, const std::vector<std::string>& signatures);
    std::vector<std::string> extract_blocked_patterns(const std::string& response);
    double calculate_payload_complexity(const std::string& payload);
    std::string normalize_payload(const std::string& payload);
    
    // Payload analysis
    bool is_sql_injection_payload(const std::string& payload);
    bool is_xss_payload(const std::string& payload);
    bool is_command_injection_payload(const std::string& payload);
    bool is_path_traversal_payload(const std::string& payload);
    std::string detect_payload_category(const std::string& payload);
}

} // namespace BlackNurse