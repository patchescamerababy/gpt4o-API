#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <functional>
#include <httplib.h>

namespace Utils {
    // 发送错误响应
    void send_error(httplib::Response& res, const std::string& message, int http_code);
    
    // 带重试的下载图片并转换为data URI
    std::string download_to_data_uri_with_retry(
        const std::string& url,
        int max_retries,
        long initial_backoff_ms,
        long per_attempt_delay_ceil_ms,
        std::function<bool()> overall_time_budget_ok
    );
    
    // 单次下载转data URI
    std::string download_once_to_data_uri(const std::string& image_url);
    
    // 从URL猜测图片内容类型
    std::string guess_image_content_type_from_url(const std::string& url);
    
    // 构建HTTP请求（简化：只需 jwt 和 body）
    std::string build_request_body(const std::string& jwt, const std::string& body);

    // 初始化并缓存一次从上游获取的 JWT（在程序启动时调用）
    void init_token_cache();
    // 获取缓存的 JWT，如果尚未初始化或为空则返回 null json
    nlohmann::json get_cached_token();
    
    // 获取token
    nlohmann::json get_token();
    
    // Base64URL解码
    std::vector<uint8_t> base64url_decode(const std::string& input);
    
    // UUID生成
    std::string generate_uuid();
}
