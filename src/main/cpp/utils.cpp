#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "utils.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <random>
#include <algorithm>
#include <cctype>

using json = nlohmann::json;

// CURL写回调函数
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::vector<char>* data) {
    size_t total_size = size * nmemb;
    data->insert(data->end(), (char*)contents, (char*)contents + total_size);
    return total_size;
}

// Base64编码
std::string base64_encode(const std::vector<char>& data) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    const char* bytes_to_encode = data.data();
    int in_len = data.size();
    
    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for(i = 0; (i <4) ; i++)
                ret += chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';
            
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (j = 0; (j < i + 1); j++)
            ret += chars[char_array_4[j]];
            
        while((i++ < 3))
            ret += '=';
    }
    
    return ret;
}

namespace Utils {

void send_error(httplib::Response& res, const std::string& message, int http_code) {
    json error;
    error["error"] = message;
    res.status = http_code;
    res.set_header("Content-Type", "application/json; charset=utf-8");
    res.body = error.dump();
}

std::string download_to_data_uri_with_retry(
    const std::string& url,
    int max_retries,
    long initial_backoff_ms,
    long per_attempt_delay_ceil_ms,
    std::function<bool()> overall_time_budget_ok
) {
    long backoff = initial_backoff_ms;
    int attempt = 0;
    
    while (true) {
        if (overall_time_budget_ok && !overall_time_budget_ok()) {
            throw std::runtime_error("下载超出整体时间预算");
        }
        
        try {
            return download_once_to_data_uri(url);
        } catch (const std::exception& e) {
            attempt++;
            if (attempt > max_retries) {
                throw std::runtime_error("多次重试仍失败: " + std::string(e.what()));
            }
            
            // 指数退避 + 抖动
            long delay = std::min(backoff, per_attempt_delay_ceil_ms);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 250);
            delay += dis(gen);
            
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            backoff = std::min(backoff * 2, per_attempt_delay_ceil_ms);
        }
    }
}

std::string download_once_to_data_uri(const std::string& image_url) {
    CURL* curl;
    CURLcode res;
    std::vector<char> data;
    std::string content_type;
    
    curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("CURL初始化失败");
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, image_url.c_str());
    // 强制不走任何代理
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    res = curl_easy_perform(curl);
    
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    char* ct;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
    if (ct) content_type = ct;
    
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        throw std::runtime_error("CURL请求失败: " + std::string(curl_easy_strerror(res)));
    }
    
    if (response_code != 200) {
        throw std::runtime_error("HTTP " + std::to_string(response_code));
    }
    
    if (content_type.empty() || content_type.find("image/") == std::string::npos) {
        content_type = guess_image_content_type_from_url(image_url);
    }
    if (content_type.empty() || content_type.find("image/") == std::string::npos) {
        content_type = "image/png";
    }
    
    std::string base64_image = base64_encode(data);
    return "data:" + content_type + ";base64," + base64_image;
}

std::string guess_image_content_type_from_url(const std::string& url) {
    std::string lower_url = url;
    std::transform(lower_url.begin(), lower_url.end(), lower_url.begin(), ::tolower);
    
    if (lower_url.find(".png") != std::string::npos) return "image/png";
    if (lower_url.find(".jpg") != std::string::npos || lower_url.find(".jpeg") != std::string::npos) return "image/jpeg";
    if (lower_url.find(".gif") != std::string::npos) return "image/gif";
    if (lower_url.find(".webp") != std::string::npos) return "image/webp";
    if (lower_url.find(".bmp") != std::string::npos) return "image/bmp";
    if (lower_url.find(".tif") != std::string::npos || lower_url.find(".tiff") != std::string::npos) return "image/tiff";
    
    return "";
}

std::string build_request_body(const std::string& jwt, const std::string& body) {
    // 参数当前未被直接使用；显式标记以避免编译器警告
    (void)jwt;
    // 这个函数在Java中返回Request对象，但在C++中我们返回完整的请求信息
    // 实际使用时需要配合CURL进行HTTP请求
    return body; // 简化实现，实际应该构建完整的HTTP请求
}

nlohmann::json get_token() {
    CURL* curl;
    CURLcode res;
    std::vector<char> data;
    
    curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("CURL初始化失败");
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://python-app-qjk4mlqqha-uc.a.run.app/token");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: AIGE/192 CFNetwork/1568.200.51 Darwin/24.1.0");
    headers = curl_slist_append(headers, "x-api-key: 07D76661F-9337-462F-8645-D8866290F8D8-AI");
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Accept-Language: zh-CN,zh-Hans;q=0.9");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // 强制不走任何代理
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    
    res = curl_easy_perform(curl);
    
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        throw std::runtime_error("token请求失败: " + std::string(curl_easy_strerror(res)));
    }
    
    if (response_code != 200) {
        throw std::runtime_error("token请求失败: HTTP " + std::to_string(response_code));
    }
    
    std::string response_str(data.begin(), data.end());
    return json::parse(response_str);
}

static std::atomic<bool> token_cache_initialized{false};
static nlohmann::json token_cache;

// 初始化并缓存一次从上游获取的 JWT（在程序启动时调用）
void init_token_cache() {
    try {
        token_cache = get_token();
        token_cache_initialized.store(true);
    } catch (const std::exception& e) {
        std::cerr << "Warning: init_token_cache failed: " << e.what() << std::endl;
        token_cache = nullptr;
        token_cache_initialized.store(false);
    }
}

// 获取缓存的 JWT，如果尚未初始化或为空则返回 null json
nlohmann::json get_cached_token() {
    if (token_cache_initialized.load()) {
        return token_cache;
    }
    return nullptr;
}

// Base64URL 解码
std::vector<uint8_t> base64url_decode(const std::string& input) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64 = input;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4 != 0) b64 += '=';
    std::vector<uint8_t> out;
    int val=0, valb=-8;
    for (unsigned char c : b64) {
        if (std::isspace(c)) continue;
        int d = base64_chars.find(c);
        if (d == (int)std::string::npos) {
            if (c == '=') break;
            throw std::runtime_error("Invalid base64url char");
        }
        val = (val<<6) + d;
        valb += 6;
        if (valb>=0) {
            out.push_back((val>>valb)&0xFF);
            valb-=8;
        }
    }
    return out;
}

// UUID生成
std::string generate_uuid() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);
    
    std::stringstream ss;
    int i;
    ss << std::hex;
    for (i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4";
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    ss << dis2(gen);
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (i = 0; i < 12; i++) {
        ss << dis(gen);
    };
    return ss.str();
}

}  // namespace Utils
