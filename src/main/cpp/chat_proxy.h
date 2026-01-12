#pragma once

#include <string>
#include <memory>
#include <vector>
#include <nlohmann/json.hpp>
#include <httplib.h>

// 线程池/任务
#include <thread>
#include <mutex>
#include <future>
#include <optional>
#include <chrono>
#include <functional>

class ChatProxy {
public:
    ChatProxy();
    // 处理一个HTTP请求
    void handle(const httplib::Request& req, httplib::Response& res);

private:
    // JWT token 及其过期时间
    std::string token_;
    int64_t token_exp_;

    // 刷新Token
    void refresh_token();

    // 确保token有效
    void ensure_valid_token();

    // 消息预处理、图片处理
    void preprocess_messages(nlohmann::json& request_json);

    // 是否有任意图片URL
    bool has_any_image_url(const nlohmann::json& message);

    // 消息规范化
    nlohmann::json normalize_message(const nlohmann::json& message);

    // 构建各类SSE块辅助函数
    std::string build_initial_sse_chunk(const std::string& convo_id, const std::string& system_fingerprint);
    std::string build_content_sse_chunk(const std::string& delta_content, const std::string& convo_id, const std::string& system_fingerprint);
    std::string build_finish_sse_chunk(const std::string& convo_id, const std::string& system_fingerprint);
    std::string build_usage_sse_chunk(const std::string& convo_id, int prompt_tokens, int completion_tokens, int total_tokens, const std::string& system_fingerprint);

    // 流式和普通响应处理
    void handle_stream_response(const httplib::Request& req, httplib::Response& res, bool need_usage_chunk);
    void handle_normal_response(const httplib::Request& req, httplib::Response& res);

    // 线程安全相关
    std::mutex token_mutex_;

    // 线程池（简单实现，仅作示例）
    std::vector<std::thread> thread_pool_;
};
