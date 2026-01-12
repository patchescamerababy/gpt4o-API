#include "chat_proxy.h"
#include "utils.h"
#include <curl/curl.h>
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

static std::once_flag g_curl_init_flag;

static void ensure_curl_global_init() {
    std::call_once(g_curl_init_flag, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

static bool should_retry_handshake(CURLcode rc, const char* errbuf) {
    // 覆盖常见 TLS/握手失败场景（包含 “Remote host terminated the handshake”）
    if (rc == CURLE_SSL_CONNECT_ERROR || rc == CURLE_SSL_CACERT || rc == CURLE_PEER_FAILED_VERIFICATION) {
        return true;
    }
    if (!errbuf || errbuf[0] == '\0') return false;

    std::string s(errbuf);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });

    if (s.find("handshake") != std::string::npos) return true;
    if (s.find("tls") != std::string::npos && s.find("alert") != std::string::npos) return true;
    if (s.find("connection was reset") != std::string::npos) return true;
    return false;
}


ChatProxy::ChatProxy() {
    ensure_curl_global_init();

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
    std::cout << "[DEBUG] handle: ENTER, method=" << req.method << std::endl;
    std::cout.flush();
    ensure_valid_token();
    std::cout << "[DEBUG] handle: token validated" << std::endl;
    std::cout.flush();
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
        
        // 关键：必须把“预处理后的 request_json”发送给上游（对齐 Java 行为）
        const std::string upstream_request_body = request_json.dump();
        std::cout << "[DEBUG] handle: upstream_request_body size=" << upstream_request_body.size() << std::endl;
        std::cout << "[DEBUG] handle: is_stream=" << is_stream << std::endl;
        std::cout.flush();

        if (is_stream) {
            std::cout << "[DEBUG] handle: calling handle_stream_response..." << std::endl;
            std::cout.flush();
            handle_stream_response(upstream_request_body, res, need_usage_chunk);
            std::cout << "[DEBUG] handle: handle_stream_response returned" << std::endl;
        } else {
            std::cout << "[DEBUG] handle: calling handle_normal_response..." << std::endl;
            std::cout.flush();
            handle_normal_response(upstream_request_body, res);
            std::cout << "[DEBUG] handle: handle_normal_response returned" << std::endl;
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

void ChatProxy::handle_stream_response(const std::string& request_body, httplib::Response& res, bool need_usage_chunk) {
    std::cout << "[DEBUG] handle_stream_response: ENTER" << std::endl;
    // 关键修复：立刻拷贝 request_body 到局部变量，避免 lambda 异步访问时悬空
    const std::string request_body_copy = request_body;
    std::cout << "[DEBUG] handle_stream_response: request_body_copy size=" << request_body_copy.size() << std::endl;
    json req_json = json::parse(request_body_copy);
    std::cout << "[DEBUG] handle_stream_response: parsed JSON" << std::endl;

    // 计算prompt tokens（与Java版本对齐，近似算法）
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
        int char_count = static_cast<int>(prompt_text.length());
        int chinese_chars = 0;
        for (char c : prompt_text) {
            if ((unsigned char)c > 127) chinese_chars++;
        }
        int english_chars = char_count - chinese_chars;
        prompt_tokens = (english_chars / 4) + (chinese_chars * 2 / 3);
        if (prompt_tokens < char_count / 6) prompt_tokens = char_count / 6;
    }

    try {
        std::cout << "[DEBUG] handle_stream_response: entering try block" << std::endl;
        const std::string upstream_url = "https://python-app-qjk4mlqqha-uc.a.run.app/ai/chat/completion";
        std::cout << "[DEBUG] handle_stream_response: upstream_url=" << upstream_url << std::endl;

        // ========== 关键对齐 Java：先探测上游状态码，不成功则“直接返回上游响应体”，不要发 SSE ==========
        std::string probe_body;
        std::string probe_content_type;

        auto write_cb_str = [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* out = static_cast<std::string*>(userdata);
            size_t n = size * nmemb;
            out->append(ptr, n);
            return n;
        };

        auto header_cb_ct = [](char* buffer, size_t size, size_t nitems, void* userdata) -> size_t {
            size_t n = size * nitems;
            auto* ct = static_cast<std::string*>(userdata);
            if (!ct) return n;

            std::string line(buffer, buffer + n);
            auto tolower_str = [](std::string s) {
                std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
                return s;
            };
            std::string lower = tolower_str(line);
            const std::string key = "content-type:";
            if (lower.rfind(key, 0) == 0) {
                std::string v = line.substr(key.size());
                auto l = v.find_first_not_of(" \t");
                auto r = v.find_last_not_of(" \t\r\n");
                if (l != std::string::npos && r != std::string::npos && r >= l) {
                    *ct = v.substr(l, r - l + 1);
                }
            }
            return n;
        };

        long probe_code = 0;
        {
            std::cout << "[DEBUG] handle_stream_response: starting probe request" << std::endl;

            CURLcode rc = CURLE_OK;
            char errbuf[CURL_ERROR_SIZE];
            errbuf[0] = '\0';

            for (int attempt = 1; attempt <= 3; ++attempt) {
                if (attempt > 1) {
                    std::cout << "[WARN] handle_stream_response: probe handshake error, retry attempt " << attempt << std::endl;
                    probe_body.clear();
                    probe_content_type.clear();
                    probe_code = 0;
                    errbuf[0] = '\0';
                    std::this_thread::sleep_for(std::chrono::milliseconds(150L * attempt));
                }

                CURL* curl = curl_easy_init();
                if (!curl) throw std::runtime_error("CURL初始化失败");
                std::cout << "[DEBUG] handle_stream_response: probe curl initialized (attempt " << attempt << ")" << std::endl;

                struct curl_slist* headers = nullptr;
                headers = curl_slist_append(headers, "Accept: application/json");
                headers = curl_slist_append(headers, "Content-Type: application/json; charset=utf-8");
                headers = curl_slist_append(headers, "x-api-key: 07D76661F-9337-462F-8645-D8866290F8D8-AI");
                headers = curl_slist_append(headers, "User-Agent: AIGE/2.5.0 (com.botai.chat; build:192; iOS 18.1.1) Alamofire/5.9.1");
                headers = curl_slist_append(headers, "Accept-Language: zh-Hans-HK;q=1.0, ja-HK;q=0.9, zh-Hant-TW;q=0.8, en-HK;q=0.7, wuu-Hans-HK;q=0.6");

                std::string auth = "Authorization: " + token_;
                headers = curl_slist_append(headers, auth.c_str());

                curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
                curl_easy_setopt(curl, CURLOPT_URL, upstream_url.c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body_copy.c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request_body_copy.size());
                curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
                curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

                // Debug: proxy + no cert verify (disabled)
                // curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:5257");
                // curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
                // 强制 HTTPS 走 HTTP proxy tunnel（CONNECT）
                // curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

                // accept gzip and auto-decompress
                curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +write_cb_str);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &probe_body);

                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, +header_cb_ct);
                curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe_content_type);

                std::cout << "[DEBUG] handle_stream_response: probe curl_easy_perform... (attempt " << attempt << ")" << std::endl;
                rc = curl_easy_perform(curl);
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &probe_code);
                std::cout << "[DEBUG] handle_stream_response: probe completed, code=" << probe_code << " rc=" << rc << " (" << curl_easy_strerror(rc) << ")" << std::endl;
                if (errbuf[0] != '\0') {
                    std::cout << "[DEBUG] handle_stream_response: probe errbuf=" << errbuf << std::endl;
                }

                curl_slist_free_all(headers);
                curl_easy_cleanup(curl);

                if (rc == CURLE_OK) break;

                if (attempt < 3 && should_retry_handshake(rc, errbuf)) {
                    continue;
                }

                break;
            }

            if (rc != CURLE_OK) {
                std::string msg = std::string("curl probe failed: ") + curl_easy_strerror(rc);
                if (errbuf[0] != '\0') {
                    msg += std::string(" | ") + errbuf;
                }
                msg += std::string(" | proxy=http://127.0.0.1:5257 tunnel=1 url=") + upstream_url;
                throw std::runtime_error(msg);
            }
        }

        if (!(probe_code >= 200 && probe_code < 300)) {
            // Java 逻辑：upstream 非 2xx 时，直接返回上游响应体（不要 SSE）
            res.status = (int)probe_code;
            if (!probe_content_type.empty()) {
                res.set_header("Content-Type", probe_content_type.c_str());
            } else {
                res.set_header("Content-Type", "application/json; charset=utf-8");
            }
            res.body = probe_body;
            return;
        }

        // ========== 上游成功：开始 SSE ==========
        res.set_header("Content-Type", "text/event-stream; charset=utf-8");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");

        const std::string convo_id = "chatcmpl-" + Utils::generate_uuid().substr(0, 24);
        const std::string system_fingerprint = "fp_" + Utils::generate_uuid().substr(0, 12);

        // 关键修复：CurlStreamCtx 必须持有 convo_id/system_fingerprint 的**拷贝**，
        // 不能是引用，否则 lambda 异步执行时原 string 已被销毁
        struct CurlStreamCtx {
            httplib::DataSink* sink;
            ChatProxy* self;
            std::string convo_id;       // 持有拷贝
            std::string system_fingerprint; // 持有拷贝
            bool need_usage;
            std::string completion_buffer;
            bool write_ok;
            bool any_data;
        };

        auto write_cb = [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* ctx = static_cast<CurlStreamCtx*>(userdata);
            size_t n = size * nmemb;
            if (n == 0 || !ctx || !ctx->sink) return 0;
            if (!ctx->write_ok) return 0;

            std::string delta(ptr, ptr + n);
            ctx->any_data = true;
            std::cout << delta << std::flush;

            if (ctx->need_usage) {
                ctx->completion_buffer += delta;
            }

            std::string sse = ctx->self->build_content_sse_chunk(delta, ctx->convo_id, ctx->system_fingerprint);
            if (!ctx->sink->write(sse.c_str(), sse.size())) {
                // 客户端断开/底层 sink 失效：立刻标记并让 curl 停止写入
                ctx->write_ok = false;
                return 0;
            }
            return n;
        };

        std::cout << "[DEBUG] handle_stream_response: setting chunked_content_provider" << std::endl;
        res.set_chunked_content_provider(
            "text/event-stream; charset=utf-8",
            [=, this, &res](size_t /*offset*/, httplib::DataSink& sink) -> bool {
                std::cout << "[DEBUG] Lambda: ENTER" << std::endl;
                std::string initial = build_initial_sse_chunk(convo_id, system_fingerprint);
                if (!sink.write(initial.c_str(), initial.size())) {
                    return false;
                }

                CURL* curl = curl_easy_init();
                if (!curl) {
                    res.status = 502;
                    return false;
                }

                struct curl_slist* headers = nullptr;
                headers = curl_slist_append(headers, "Accept: application/json");
                headers = curl_slist_append(headers, "Content-Type: application/json; charset=utf-8");
                headers = curl_slist_append(headers, "x-api-key: 07D76661F-9337-462F-8645-D8866290F8D8-AI");
                headers = curl_slist_append(headers, "User-Agent: AIGE/2.5.0 (com.botai.chat; build:192; iOS 18.1.1) Alamofire/5.9.1");
                headers = curl_slist_append(headers, "Accept-Language: zh-Hans-HK;q=1.0, ja-HK;q=0.9, zh-Hant-TW;q=0.8, en-HK;q=0.7, wuu-Hans-HK;q=0.6");

                std::cout << "[DEBUG] Lambda: preparing auth header" << std::endl;
                std::string auth = "Authorization: " + token_;
                std::cout << "[DEBUG] Lambda: auth prepared, token_ length=" << token_.length() << std::endl;
                headers = curl_slist_append(headers, auth.c_str());

                // 关键：必须拷贝 convo_id/system_fingerprint 进 ctx（不能用引用/指针）
                CurlStreamCtx ctx;
                ctx.sink = &sink;
                ctx.self = const_cast<ChatProxy*>(this);
                ctx.convo_id = convo_id;  // 拷贝构造
                ctx.system_fingerprint = system_fingerprint;  // 拷贝构造
                ctx.need_usage = need_usage_chunk;
                ctx.completion_buffer = "";
                ctx.write_ok = true;
                ctx.any_data = false;

                CURLcode rc = CURLE_OK;
                long http_code = 0;
                char errbuf[CURL_ERROR_SIZE];

                for (int attempt = 1; attempt <= 3; ++attempt) {
                    if (attempt > 1) {
                        std::cout << "[WARN] Lambda: handshake error, retry attempt " << attempt << std::endl;
                        ctx.write_ok = true;
                        ctx.any_data = false;
                        http_code = 0;
                        std::this_thread::sleep_for(std::chrono::milliseconds(150L * attempt));
                    }

                    errbuf[0] = '\0';
                    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
                    curl_easy_setopt(curl, CURLOPT_URL, upstream_url.c_str());
                    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                    curl_easy_setopt(curl, CURLOPT_POST, 1L);
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body_copy.c_str());
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request_body_copy.size());
                    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
                    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

                    // curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:5257");
                    // curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
                    // 强制 HTTPS 走 HTTP proxy tunnel（CONNECT）
                    // curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
                    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

                    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +write_cb);
                    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

                    std::cout << "[DEBUG] Lambda: calling curl_easy_perform... (attempt " << attempt << ")" << std::endl;
                    rc = curl_easy_perform(curl);
                    std::cout << "[DEBUG] Lambda: curl_easy_perform returned, rc=" << rc << " (" << curl_easy_strerror(rc) << ")" << std::endl;
                    if (errbuf[0] != '\0') {
                        std::cout << "[DEBUG] Lambda: errbuf=" << errbuf << std::endl;
                    }

                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

                    if (rc == CURLE_OK) break;

                    // 仅在还没输出任何数据时重试（避免重复向客户端输出）
                    if (attempt < 3 && !ctx.any_data && should_retry_handshake(rc, errbuf)) {
                        continue;
                    }

                    break;
                }

                curl_slist_free_all(headers);
                curl_easy_cleanup(curl);

                // 如果 write_cb 已经检测到 sink 失效（例如客户端断开），不要再继续对 sink.write()，否则可能触发崩溃
                if (!ctx.write_ok) {
                    res.status = 499; // client closed request（非标准，但用于区分）
                    sink.done();
                    return false;
                }

                if (rc != CURLE_OK) {
                    // curl 写失败/网络失败：同样不要再写 finish/usage/done（避免在异常状态下触发 httplib 内部崩溃）
                    res.status = 502;
                    sink.done();
                    return false;
                }

                if (!(http_code >= 200 && http_code < 300)) {
                    // 理论上 probe 已 2xx，但这里兜底：结束 SSE
                    res.status = (int)http_code;
                } else {
                    res.status = 200;
                }

                // 下面开始写 SSE 结束块：任何一次写失败都立即停止
                std::string finish = build_finish_sse_chunk(convo_id, system_fingerprint);
                if (!sink.write(finish.c_str(), finish.size())) {
                    sink.done();
                    return false;
                }

                if (need_usage_chunk) {
                    int completionTokens = 0;
                    if (!ctx.completion_buffer.empty()) {
                        int char_count = static_cast<int>(ctx.completion_buffer.length());
                        int chinese_chars = 0;
                        for (char c : ctx.completion_buffer) {
                            if ((unsigned char)c > 127) chinese_chars++;
                        }
                        int english_chars = char_count - chinese_chars;
                        completionTokens = (english_chars / 4) + (chinese_chars * 2 / 3);
                        if (completionTokens < char_count / 6) completionTokens = char_count / 6;
                    }
                    int totalTokens = prompt_tokens + completionTokens;
                    std::string usage = build_usage_sse_chunk(convo_id, prompt_tokens, completionTokens, totalTokens, system_fingerprint);
                    if (!sink.write(usage.c_str(), usage.size())) {
                        sink.done();
                        return false;
                    }
                }

                std::string done = "data: [DONE]\n\n";
                if (!sink.write(done.c_str(), done.size())) {
                    sink.done();
                    return false;
                }

                sink.done();
                return true;
            },
            [](bool /*success*/) {}
        );
    } catch (const std::exception& e) {
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.status = 502;
        nlohmann::json err;
        err["error"] = "Upstream request failed";
        err["detail"] = e.what();
        res.body = err.dump();
    }
}

void ChatProxy::handle_normal_response(const std::string& request_body, httplib::Response& res) {
    std::cout << "[DEBUG] handle_normal_response: ENTER, request_body size=" << request_body.size() << std::endl;
    std::cout.flush();
    try {
        const std::string upstream_url = "https://python-app-qjk4mlqqha-uc.a.run.app/ai/chat/completion";
        std::cout << "[DEBUG] handle_normal_response: upstream_url=" << upstream_url << std::endl;

        CURL* curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("CURL初始化失败");
        }

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json; charset=utf-8");
        headers = curl_slist_append(headers, "x-api-key: 07D76661F-9337-462F-8645-D8866290F8D8-AI");
        headers = curl_slist_append(headers, "User-Agent: AIGE/2.5.0 (com.botai.chat; build:192; iOS 18.1.1) Alamofire/5.9.1");
        headers = curl_slist_append(headers, "Accept-Language: zh-Hans-HK;q=1.0, ja-HK;q=0.9, zh-Hant-TW;q=0.8, en-HK;q=0.7, wuu-Hans-HK;q=0.6");

        std::string auth = "Authorization: " + token_;
        headers = curl_slist_append(headers, auth.c_str());

        std::string response_body;

        // capture upstream Content-Type for transparent pass-through
        std::string upstream_content_type;

        auto write_cb = [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* out = static_cast<std::string*>(userdata);
            if (!out) {
                std::cout << "[ERROR] write_cb: userdata is NULL!" << std::endl;
                return 0;
            }
            size_t n = size * nmemb;
            std::cout << "[DEBUG] write_cb: received " << n << " bytes" << std::endl;
            try {
                out->append(ptr, n);
                std::cout << "[DEBUG] write_cb: appended successfully, total size now=" << out->size() << std::endl;
                return n;
            } catch (const std::exception& e) {
                std::cout << "[ERROR] write_cb: exception: " << e.what() << std::endl;
                return 0;
            }
        };

        auto header_cb = [](char* buffer, size_t size, size_t nitems, void* userdata) -> size_t {
            size_t n = size * nitems;
            auto* ct = static_cast<std::string*>(userdata);
            if (!ct) return n;

            std::string line(buffer, buffer + n);
            // very small parser: look for "Content-Type:" case-insensitive
            auto tolower_str = [](std::string s) {
                std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
                return s;
            };
            std::string lower = tolower_str(line);
            const std::string key = "content-type:";
            if (lower.rfind(key, 0) == 0) {
                std::string v = line.substr(key.size());
                // trim
                auto l = v.find_first_not_of(" \t");
                auto r = v.find_last_not_of(" \t\r\n");
                if (l != std::string::npos && r != std::string::npos && r >= l) {
                    *ct = v.substr(l, r - l + 1);
                }
            }
            return n;
        };

        char errbuf[CURL_ERROR_SIZE];
        errbuf[0] = '\0';
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        curl_easy_setopt(curl, CURLOPT_URL, upstream_url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request_body.size());
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

        // Debug: proxy + no cert verify
        // curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:5257");
        // curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        // 强制 HTTPS 走 HTTP proxy tunnel（CONNECT）
        // curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // accept gzip and auto-decompress
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, +header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &upstream_content_type);

        CURLcode rc = CURLE_OK;

        for (int attempt = 1; attempt <= 3; ++attempt) {
            if (attempt > 1) {
                std::cout << "[WARN] handle_normal_response: handshake error, retry attempt " << attempt << std::endl;
                response_body.clear();
                upstream_content_type.clear();
                errbuf[0] = '\0';
                std::this_thread::sleep_for(std::chrono::milliseconds(150L * attempt));
            }

            std::cout << "[DEBUG] handle_normal_response: calling curl_easy_perform... (attempt " << attempt << ")" << std::endl;
            std::cout.flush();
            rc = curl_easy_perform(curl);
            std::cout << "[DEBUG] handle_normal_response: curl_easy_perform returned, rc=" << rc << " (" << curl_easy_strerror(rc) << ")" << std::endl;
            if (errbuf[0] != '\0') {
                std::cout << "[DEBUG] handle_normal_response: errbuf=" << errbuf << std::endl;
            }

            if (rc == CURLE_OK) break;

            if (attempt < 3 && should_retry_handshake(rc, errbuf)) {
                continue;
            }

            break;
        }

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (rc != CURLE_OK) {
            std::string msg = std::string("curl failed: ") + curl_easy_strerror(rc);
            if (errbuf[0] != '\0') {
                msg += std::string(" | errbuf=") + errbuf;
            }
            msg += std::string(" | proxy=http://127.0.0.1:5257 tunnel=1 url=") + upstream_url;
            std::cout << "[ERROR] " << msg << std::endl;
            std::cout.flush();
            throw std::runtime_error(msg);
        }
        std::cout << "[DEBUG] handle_normal_response: http_code=" << http_code << std::endl;
        if (http_code <= 0) {
            // should not happen if rc == OK, but keep consistent
            res.status = 502;
            res.set_header("Content-Type", "application/json; charset=utf-8");
            nlohmann::json err;
            err["error"] = "Upstream request failed";
            err["detail"] = "No HTTP status";
            res.body = err.dump();
            return;
        }

        // 原封返回上游：status + body + Content-Type（如果上游没给就默认 json）
        res.status = (int)http_code;
        if (!upstream_content_type.empty()) {
            res.set_header("Content-Type", upstream_content_type.c_str());
        } else {
            res.set_header("Content-Type", "application/json; charset=utf-8");
        }
        res.body = response_body;
    } catch (const std::exception& e) {
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.status = 502;
        nlohmann::json err;
        err["error"] = "Upstream request failed";
        err["detail"] = e.what();
        res.body = err.dump();
    }
}

void ChatProxy::preprocess_messages(nlohmann::json& request_json) {
    // 已在handle函数中实现
    (void)request_json; // 避免未使用参数警告
}
