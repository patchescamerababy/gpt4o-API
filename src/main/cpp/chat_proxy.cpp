#include "chat_proxy.h"
#include "utils.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <string>
#include <mutex>
#include <chrono>
#include <ctime>
#include <random>
#include <iomanip>
#include <cctype>
#include <cstdint>
#include <future>
#include <thread>
#include <regex>

using json = nlohmann::json;



ChatProxy::ChatProxy() {
    // Prefer cached token initialized at startup; fall back to active refresh.
    try {
        nlohmann::json cached = Utils::get_cached_token();
        if (!cached.is_null() && cached.contains("access_token")) {
            std::string newToken = cached.value("access_token", "");
            if (!newToken.empty()) {
                auto dot1 = newToken.find('.');
                auto dot2 = newToken.find('.', dot1 + 1);
                if (dot1 != std::string::npos && dot2 != std::string::npos) {
                    std::string payloadB64 = newToken.substr(dot1 + 1, dot2 - dot1 - 1);
                    std::vector<uint8_t> decoded = Utils::base64url_decode(payloadB64);
                    std::string payload(reinterpret_cast<const char*>(decoded.data()), decoded.size());
                    json payload_json = json::parse(payload);
                    if (payload_json.contains("exp")) {
                        this->token_ = newToken;
                        this->token_exp_ = payload_json.value("exp", 0LL);
                        if (this->token_exp_) {
                            return;
                        }
                    }
                }
            }
        }
    } catch (...) {
        // Fall back to refresh_token on any error
    }

    // If cache unavailable or invalid, refresh synchronously
    refresh_token();
}

void ChatProxy::refresh_token() {
    std::lock_guard<std::mutex> lock(token_mutex_);
    json bearer = Utils::get_token();
    if (bearer.is_null() || !bearer.contains("access_token")) {
        throw std::runtime_error("无法获取新的Token");
    }
    std::string newToken = bearer.value("access_token", "");
    if (newToken.empty()) throw std::runtime_error("access_token为空");
    
    auto dot1 = newToken.find('.');
    auto dot2 = newToken.find('.', dot1+1);
    if (dot1==std::string::npos || dot2==std::string::npos) 
        throw std::runtime_error("无效的JWT格式");
    std::string payloadB64 = newToken.substr(dot1+1, dot2-dot1-1);
    
    std::vector<uint8_t> decoded = Utils::base64url_decode(payloadB64);
    std::string payload(reinterpret_cast<const char*>(decoded.data()), decoded.size());
    json payload_json = json::parse(payload);
    if (!payload_json.contains("exp")) throw std::runtime_error("JWT payload中未包含exp");
    this->token_ = newToken;
    this->token_exp_ = payload_json.value("exp", 0LL);
    if (!this->token_exp_) throw std::runtime_error("提取到的exp无效");
}

void ChatProxy::ensure_valid_token() {
    std::lock_guard<std::mutex> lock(token_mutex_);

    std::time_t now_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    int64_t now = static_cast<int64_t>(now_t);

    if (token_.empty() || now >= token_exp_) {
        refresh_token();
    }

    int remaining = static_cast<int>(token_exp_ - now);
    std::time_t exp_t = static_cast<std::time_t>(token_exp_);

    char expbuf[32], nowbuf[32];
    std::strftime(expbuf, sizeof(expbuf), "%Y/%m/%d %H:%M:%S", std::localtime(&exp_t));
    std::strftime(nowbuf, sizeof(nowbuf), "%Y/%m/%d %H:%M:%S", std::localtime(&now_t));
    std::cout << "\n  Current  time: " << nowbuf << "\nExpiration time: " << expbuf;
    std::cout << "\nRemaining: " << (remaining / 60) << " minutes " << (remaining % 60) << " seconds" << std::endl;
}

void ChatProxy::handle(const httplib::Request& req, httplib::Response& res) {
    ensure_valid_token();
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    
    std::string method = req.method;
    if (method == "OPTIONS") {
        res.status = 204;
        return;
    }
    if (method == "GET") {
std::string html = R"(
            <html><head><title>欢迎使用API</title></head>
            <body><h1>欢迎使用API</h1>
            <p>此 API 用于与 ChatGPT / Claude 模型交互。您可以发送消息给模型并接收响应。</p>
            </body></html>
        )";
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.status = 200;
        res.body = html;
        return;
    }
    if (method != "POST") {
        res.status = 405;
        return;
    }

    try {
        json req_json = json::parse(req.body);
        if (!req_json.contains("messages")) {
            Utils::send_error(res, "Missing messages field", 400);
            return;
        }
        
        json messages = req_json["messages"];
        std::string model_name = req_json.value("model", "gpt-4o");
        bool is_stream = req_json.value("stream", false);
        
        json request_json = req_json;
        
        bool need_usage_chunk = false;
        if (req_json.contains("stream_options")) {
            json stream_options = req_json["stream_options"];
            need_usage_chunk = stream_options.value("include_usage", false);
        }
        
        if (messages.is_array()) {
            json new_messages = json::array();
            
            // 处理图片下载
            std::vector<std::future<void>> image_tasks;
            const long OVERALL_DEADLINE_MS = 120000L;
            const long overall_deadline_ms = OVERALL_DEADLINE_MS; // 用于 lambda capture，避免 clang -Wunused-lambda-capture 告警
            auto start_time = std::chrono::steady_clock::now();
            
            for (auto& message : messages) {
                if (message.contains("content") && message["content"].is_array()) {
                    json& content_array = message["content"];
                    for (auto& content_item : content_array) {
                        if (content_item.contains("type") && content_item["type"] == "image_url") {
                            if (content_item.contains("image_url") && content_item["image_url"].contains("url")) {
                                std::string image_url = content_item["image_url"]["url"];
                                if (!image_url.empty() && image_url.find("data:image/") != 0) {
                                    auto task = std::async(std::launch::async, [&content_item, image_url, start_time, overall_deadline_ms]() {
                                        try {
                                            std::string data_uri = Utils::download_to_data_uri_with_retry(
                                                image_url,
                                                8,
                                                200L,
                                                5000L,
                                                [start_time, overall_deadline_ms]() {
                                                    auto now = std::chrono::steady_clock::now();
                                                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
                                                    return elapsed.count() < overall_deadline_ms;
                                                }
                                            );
                                            content_item["image_url"]["url"] = data_uri;
                                        } catch (const std::exception& e) {
                                            throw;
                                        }
                                    });
                                    image_tasks.push_back(std::move(task));
                                }
                            }
                        }
                    }
                }
                
                json normalized = normalize_message(message);
                new_messages.push_back(normalized);
            }
            
            // 等待所有图片任务完成
            for (auto& task : image_tasks) {
                try {
                    task.get();
                } catch (const std::exception& e) {
                    Utils::send_error(res, "图片下载失败: " + std::string(e.what()), 500);
                    return;
                }
            }
            
            // 检查最后一条消息是否含图片
            if (!messages.empty()) {
                json last_msg = messages.back();
                bool last_has_image = has_any_image_url(last_msg);
                if (last_has_image) {
                    json placeholder;
                    placeholder["role"] = "user";
                    placeholder["content"] = "";
                    new_messages.push_back(placeholder);
                }
            }
            
            request_json["messages"] = new_messages;
        }
        
        if (is_stream) {
            handle_stream_response(req, res, need_usage_chunk);
        } else {
            handle_normal_response(req, res);
        }
        
    } catch (const std::exception& e) {
        Utils::send_error(res, "C++ ChatProxy 错误: " + std::string(e.what()), 500);
    }
}

bool ChatProxy::has_any_image_url(const json& message) {
    if (!message.contains("content") || !message["content"].is_array()) return false;
    for (const auto& item : message["content"]) {
        if (item.contains("type") && item["type"] == "image_url" && item.contains("image_url")) {
            return true;
        }
    }
    return false;
}

json ChatProxy::normalize_message(const json& message) {
    json result = message;
    
    if (result.contains("content") && result["content"].is_array()) {
        json content_array = result["content"];
        
        bool all_text = true;
        std::stringstream combined;
        for (size_t i = 0; i < content_array.size(); i++) {
            const auto& item = content_array[i];
            if (!item.contains("type") || item["type"] != "text" || !item.contains("text")) {
                all_text = false;
                break;
            }
            if (i > 0) combined << "\n";
            combined << item["text"].get<std::string>();
        }
        
        if (all_text) {
            json flat;
            flat["role"] = result.value("role", "");
            flat["content"] = combined.str();
            return flat;
        }
    }
    
    return result;
}

std::string ChatProxy::build_initial_sse_chunk(const std::string& convo_id, const std::string& system_fingerprint) {
    json delta;
    delta["content"] = "";
    delta["refusal"] = nullptr;
    delta["role"] = "assistant";
    
    json choice_obj;
    choice_obj["index"] = 0;
    choice_obj["delta"] = delta;
    choice_obj["finish_reason"] = nullptr;
    choice_obj["logprobs"] = nullptr;
    
    json response;
    response["id"] = convo_id;
    response["object"] = "chat.completion.chunk";
    response["created"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    response["model"] = "gpt-4o-2024-08-06";
    response["system_fingerprint"] = system_fingerprint;
    response["choices"] = json::array({choice_obj});
    response["usage"] = nullptr;
    
    return "data: " + response.dump() + "\n\n";
}

std::string ChatProxy::build_content_sse_chunk(const std::string& delta_content, const std::string& convo_id, const std::string& system_fingerprint) {
    json delta;
    if (!delta_content.empty()) {
        delta["content"] = delta_content;
    }
    
    json choice_obj;
    choice_obj["index"] = 0;
    choice_obj["delta"] = delta;
    choice_obj["finish_reason"] = nullptr;
    choice_obj["logprobs"] = nullptr;
    
    json response;
    response["id"] = convo_id;
    response["object"] = "chat.completion.chunk";
    response["created"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    response["model"] = "gpt-4o-2024-08-06";
    response["system_fingerprint"] = system_fingerprint;
    response["choices"] = json::array({choice_obj});
    response["usage"] = nullptr;
    
    return "data: " + response.dump() + "\n\n";
}

std::string ChatProxy::build_finish_sse_chunk(const std::string& convo_id, const std::string& system_fingerprint) {
    json choice_obj;
    choice_obj["index"] = 0;
    choice_obj["delta"] = json::object();
    choice_obj["finish_reason"] = "stop";
    choice_obj["logprobs"] = nullptr;
    
    json response;
    response["id"] = convo_id;
    response["object"] = "chat.completion.chunk";
    response["created"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    response["model"] = "gpt-4o-2024-08-06";
    response["system_fingerprint"] = system_fingerprint;
    response["choices"] = json::array({choice_obj});
    response["usage"] = nullptr;
    
    return "data: " + response.dump() + "\n\n";
}

std::string ChatProxy::build_usage_sse_chunk(const std::string& convo_id, int prompt_tokens, int completion_tokens, int total_tokens, const std::string& system_fingerprint) {
    json usage;
    usage["prompt_tokens"] = prompt_tokens;
    usage["completion_tokens"] = completion_tokens;
    usage["total_tokens"] = total_tokens;
    
    json prompt_tokens_details;
    prompt_tokens_details["audio_tokens"] = 0;
    prompt_tokens_details["cached_tokens"] = 0;
    usage["prompt_tokens_details"] = prompt_tokens_details;
    
    json completion_tokens_details;
    completion_tokens_details["accepted_prediction_tokens"] = 0;
    completion_tokens_details["audio_tokens"] = 0;
    completion_tokens_details["reasoning_tokens"] = 0;
    completion_tokens_details["rejected_prediction_tokens"] = 0;
    usage["completion_tokens_details"] = completion_tokens_details;
    
    json response;
    response["id"] = convo_id;
    response["object"] = "chat.completion.chunk";
    response["created"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    response["model"] = "gpt-4o-2024-08-06";
    response["system_fingerprint"] = system_fingerprint;
    response["choices"] = json::array();
    response["usage"] = usage;
    
    return "data: " + response.dump() + "\n\n";
}

void ChatProxy::handle_stream_response(const httplib::Request& req, httplib::Response& res, bool need_usage_chunk) {
    json req_json = json::parse(req.body);

    // 计算prompt tokens（与Java版本对齐）
    int prompt_tokens = 0;
    if (req_json.contains("messages")) {
        std::string prompt_text;
        for (const auto& msg : req_json["messages"]) {
            if (msg.contains("content")) {
                if (msg["content"].is_string()) {
                    prompt_text += msg["content"].get<std::string>() + "\n";
                } else if (msg["content"].is_array()) {
                    for (const auto& part : msg["content"]) {
                        if (part.contains("type") && part["type"] == "text" && part.contains("text")) {
                            prompt_text += part["text"].get<std::string>() + "\n";
                        }
                    }
                }
            }
        }
        // 使用GPT-4标准：约1token=0.75个英文单词，1个中文字符≈2-3tokens
        // 简化算法：英文按4字符/token，中文按1.5字符/token
        int char_count = static_cast<int>(prompt_text.length());
        int chinese_chars = 0;
        for (char c : prompt_text) {
            if ((unsigned char)c > 127) chinese_chars++;
        }
        int english_chars = char_count - chinese_chars;
        prompt_tokens = (english_chars / 4) + (chinese_chars * 2 / 3);
        if (prompt_tokens < char_count / 6) prompt_tokens = char_count / 6; // 最小值保护
    }

    try {
        // Build upstream request details
        const std::string upstream_host = "https://python-app-qjk4mlqqha-uc.a.run.app";
        const std::string upstream_path = "/ai/chat/completion";
        std::string request_body = req_json.dump();

        // Prepare common headers
        httplib::Headers headers;
        headers.emplace("Content-Type", "application/json");
        headers.emplace("Accept", "application/json");
        headers.emplace("User-Agent", "AIGE/2.5.0 (cpp-httplib)");
        headers.emplace("x-api-key", "07D76661F-9337-462F-8645-D8866290F8D8-AI");
        if (!token_.empty()) {
            headers.emplace("Authorization", token_); // token_ already includes the value expected by upstream
        }

        // 1) Make a non-streaming upstream request to capture actual status and body for error transparency.
        httplib::Client probe_cli(upstream_host);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        probe_cli.enable_server_certificate_verification(false);
#endif
        // Use a regular POST to get full response body and status
        auto probe_result = probe_cli.Post(upstream_path.c_str(), headers, request_body, "application/json");
        if (!probe_result) {
            // 无上游响应体可透传，返回最小纯文本错误，避免构造JSON
            res.status = 502;
            res.set_header("Content-Type", "text/plain; charset=utf-8");
            res.body = "Upstream probe failed";
            return;
        }
        int status = probe_result->status;
        if (!(status >= 200 && status < 300)) {
            // 读取并打印上游错误响应体，然后透传给下游
            std::cout << "Upstream error " << status << ": " << probe_result->body << std::endl;
            res.status = status;
            // 透传上游 Content-Type（如果有）
            auto ct_it = probe_result->headers.find("Content-Type");
            if (ct_it != probe_result->headers.end()) {
                res.set_header("Content-Type", ct_it->second.c_str());
            } else {
                res.set_header("Content-Type", "application/json; charset=utf-8");
            }
            res.body = probe_result->body;
            return;
        }

        // 2) Upstream is 2xx - stream it incrementally as SSE.
        // Use a chunked content provider that will perform a second request and forward content chunks immediately.
        res.set_header("Content-Type", "text/event-stream; charset=utf-8");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");

        // 默认假定成功为200，但如果非2xx则用上游错误码
        int stream_status_to_set = 200;

        // Generate conversation id & system fingerprint (fixed per stream)
        std::string convo_id = "chatcmpl-" + Utils::generate_uuid().substr(0, 24);
        std::string system_fingerprint = "fp_" + Utils::generate_uuid().substr(0, 12);

        // We will capture completion token counts incrementally (simplified)
        std::shared_ptr<std::atomic<int>> accumulated_completion_tokens = std::make_shared<std::atomic<int>>(0);

        // Provider: called by httplib to stream content. It should block and push SSE chunks via sink.write(...)
        res.set_chunked_content_provider("text/event-stream; charset=utf-8",
            [=, this, &res, &stream_status_to_set](size_t /*offset*/, httplib::DataSink &sink) -> bool {
                try {
                    // 1) Send initial SSE chunk
                    std::string initial = build_initial_sse_chunk(convo_id, system_fingerprint);
                    if (!sink.write(initial.c_str(), initial.size())) {
                        return false;
                    }

                    // 2) Perform upstream POST and stream body via content_receiver
                    httplib::Client stream_cli(upstream_host);
    #ifdef CPPHTTPLIB_OPENSSL_SUPPORT
                    stream_cli.enable_server_certificate_verification(false);
    #endif
                    httplib::Request stream_req;
                    stream_req.method = "POST";
                    stream_req.path = upstream_path;
                    stream_req.headers = headers;
                    stream_req.body = request_body;

                    // 用于累积所有completion内容，以便最后计算总token数
                    std::shared_ptr<std::string> completion_buffer = need_usage_chunk ? std::make_shared<std::string>() : nullptr;

                    // 用于累积所有错误内容（无论上游是否分块输出）
                    std::shared_ptr<std::string> error_buffer = std::make_shared<std::string>();

                    // content_receiver will be called as upstream body data arrives
                    stream_req.content_receiver = [=, this, &sink, &error_buffer](const char* data, size_t data_length, size_t /*offset*/, size_t /*total_length*/) -> bool {
                        if (data_length == 0) return true;
                        std::string delta(data, data_length);
                        std::cout << delta << std::flush;
                        // accumulate for completion tokens calculation
                        if (need_usage_chunk && completion_buffer) {
                            *completion_buffer += delta;
                        }
                        // accumulate for error fallback
                        *error_buffer += delta;

                        std::string sse = build_content_sse_chunk(delta, convo_id, system_fingerprint);
                        if (!sink.write(sse.c_str(), sse.size())) {
                            return false;
                        }
                        return true;
                    };

                    // Execute streaming request (this will block until upstream completes or error)
                    auto stream_result = stream_cli.send(stream_req);

                    if (!stream_result || stream_result->status < 200 || stream_result->status >= 300) {
                        // 设置下游响应码为上游错误码
                        int upstream_error_code = stream_result ? stream_result->status : 502;
                        stream_status_to_set = upstream_error_code;

                        // upstream error, surface all collected error response
                        std::string errChunk = "data: " + *error_buffer;
                        // 补齐从stream_result->body遗漏部分（极端情况下可能有）
                        if (stream_result && stream_result->body.size() && error_buffer->find(stream_result->body) == std::string::npos) {
                            errChunk += stream_result->body;
                        }
                        errChunk += "\n\n";
                        sink.write(errChunk.c_str(), errChunk.size());
                    }

                    // 3) Send finish SSE chunk
                    std::string finish = build_finish_sse_chunk(convo_id, system_fingerprint);
                    if (!sink.write(finish.c_str(), finish.size())) {
                        return false;
                    }

                    // 4) If requested, send usage chunk
                    if (need_usage_chunk && completion_buffer) {
                        // 计算completion tokens，与Java版本类似的逻辑
                        int completionTokens = 0;
                        if (!completion_buffer->empty()) {
                            int char_count = static_cast<int>(completion_buffer->length());
                            int chinese_chars = 0;
                            for (char c : *completion_buffer) {
                                if ((unsigned char)c > 127) chinese_chars++;
                            }
                            int english_chars = char_count - chinese_chars;
                            completionTokens = (english_chars / 4) + (chinese_chars * 2 / 3);
                            if (completionTokens < char_count / 6) completionTokens = char_count / 6; // 最小值保护
                        }
                        int totalTokens = prompt_tokens + completionTokens;
                        std::string usage = build_usage_sse_chunk(convo_id, prompt_tokens, completionTokens, totalTokens, system_fingerprint);
                        if (!sink.write(usage.c_str(), usage.size())) {
                            return false;
                        }
                    }

                    // 5) [DONE] marker
                    std::string done = "data: [DONE]\n\n";
                    if (!sink.write(done.c_str(), done.size())) {
                        return false;
                    }

                    // Signal completion
                    sink.done();

                    // 在收完流之后设置最终响应状态码
                    res.status = stream_status_to_set;
                    return true;
                } catch (const std::exception& e) {
                    try {
                        std::string finish2 = build_finish_sse_chunk(convo_id, system_fingerprint);
                        sink.write(finish2.c_str(), finish2.size());
                        std::string done2 = "data: [DONE]\n\n";
                        sink.write(done2.c_str(), done2.size());
                        sink.done();
                    } catch (...) {}
                    // 上游异常，状态码502
                    res.status = 502;
                    return false;
                }
            },
            // resource releaser - no-op
            [](bool /*success*/){ /* nothing to release */ }
        );

    } catch (const std::exception& e) {
        // 在这里也尽可能将上游错误透传给下游，而不是统一 Internal Server Error
        // 如果 e 是我们在请求上游时抛出的异常，通常没有现成的上游响应体。
        // 但此处至少返回可读的 JSON 错误，并保持 application/json。
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.status = 502; // Bad Gateway，表明是上游失败
        nlohmann::json err;
        err["error"] = "Upstream request failed";
        err["detail"] = e.what();
        res.body = err.dump();
    }
}

void ChatProxy::handle_normal_response(const httplib::Request& req, httplib::Response& res) {
    json req_json = json::parse(req.body);

    try {
        // 为了在非2xx时也返回上游原始错误体，这里不用 send_request 封装，改用 httplib 直接请求拿到 status+body
        const std::string upstream_host = "https://python-app-qjk4mlqqha-uc.a.run.app";
        const std::string upstream_path = "/ai/chat/completion";
        httplib::Client cli(upstream_host);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        cli.enable_server_certificate_verification(false);
#endif
        httplib::Headers headers;
        headers.emplace("Content-Type", "application/json");
        headers.emplace("Accept", "application/json");
        headers.emplace("User-Agent", "AIGE/2.5.0 (cpp-httplib)");
        headers.emplace("x-api-key", "07D76661F-9337-462F-8645-D8866290F8D8-AI");
        if (!token_.empty()) {
            headers.emplace("Authorization", token_);
        }

        auto r = cli.Post(upstream_path.c_str(), headers, req_json.dump(), "application/json");
        if (!r) {
            // 网络失败：返回 502 + 简单 JSON 说明
            res.set_header("Content-Type", "application/json; charset=utf-8");
            res.status = 502;
            nlohmann::json err;
            err["error"] = "Upstream connection failed";
            res.body = err.dump();
            return;
        }

        // 透传上游状态码与响应体
        res.status = r->status;
        auto ct_it = r->headers.find("Content-Type");
        if (ct_it != r->headers.end()) {
            res.set_header("Content-Type", ct_it->second.c_str());
        } else {
            res.set_header("Content-Type", "application/json; charset=utf-8");
        }
        res.body = r->body;
    } catch (const std::exception& e) {
        // 兜底：返回 502 + 错误详情（非上游原始体）
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.status = 502;
        nlohmann::json err;
        err["error"] = "Proxy error";
        err["detail"] = e.what();
        res.body = err.dump();
    }
}

void ChatProxy::preprocess_messages(nlohmann::json& request_json) {
    // 已在handle函数中实现
    (void)request_json; // 避免未使用参数警告
}
