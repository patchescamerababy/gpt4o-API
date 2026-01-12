/***********************
 * main.cpp
 ***********************/

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <cstdlib>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <thread>
#include <chrono>
#include <ctime>
#include <set>
#include <locale>
#include <memory>
#include <cstring>  // for memset

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

 // 第三方库
#include <httplib.h>        // https://github.com/yhirose/cpp-httplib
#include <curl/curl.h>      // libcurl
#include <nlohmann/json.hpp> // https://github.com/nlohmann/json


// 包含必要的头文件
#include "chat_proxy.h"
#include "utils.h"

using json = nlohmann::json;

// 全局变量
int port = 80;
std::string prefix = ""; // 路径前缀，默认为空

/*===========================================================
 * 外部函数声明：已修改函数签名，增加 bool hasImage 参数
 *===========================================================*/
extern void handleNormalResponse(httplib::Response& res,
    const std::string& token,
    const json& requestJson,
    bool hasImage);

extern void handleStreamResponse(httplib::Response& res,
    const std::string& token,
    const json& requestJson,
    bool hasImage);

extern void sendError(httplib::Response& res,
    const std::string& message,
    int HTTP_code);

extern void handleModels(const httplib::Request& req,
    httplib::Response& res);

// --------------------------------------------------------------------------
// 日志记录函数
// --------------------------------------------------------------------------
void logResponse(const std::string& endpoint, int status, const std::string& httpVersion, const std::string &remoteIP, int remotePort) {
    // 获取当前时间
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::stringstream time_ss;
    time_ss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S");

    // 根据状态码设置颜色
    std::string colorCode;
    if (status >= 200 && status < 400) {
        colorCode = "\033[32m";  // 绿色
    } else if (status >= 400) {
        colorCode = "\033[31m";  // 红色
    } else {
        colorCode = "\033[0m";   // 默认
    }

    // 输出日志
    std::cout << "[" << time_ss.str() << "] "
              << remoteIP << ":" << remotePort << " "
              << endpoint << " " << httpVersion << " " 
              << colorCode << status << "\033[0m" << std::endl;
}

// --------------------------------------------------------------------------
// main 函数
// --------------------------------------------------------------------------
// 打印帮助信息
void printHelp() {
    std::cout << "Usage: chatrun [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                 Display this help message" << std::endl;
    std::cout << "  -p, --port <number>        Specify the port number (default: 80)" << std::endl;
    std::cout << "  -c, --charset <charset>    Set output charset: UTF-8 or GBK (default depends on OS)" << std::endl;
    std::cout << "  -f, --prefix <prefix>      Set API path prefix, e.g. Chatrun (default: none)" << std::endl;
    std::cout << std::endl;
    std::cout << "Supported endpoints:" << std::endl;
    std::cout << "  GET  /[prefix]/v1/models                  - List supported models" << std::endl;
    std::cout << "  POST /[prefix]/v1/chat/completions        - OpenAI Chat/completion interface" << std::endl;
    std::cout << "  POST /[prefix]/v1/message                 - Claude chat/completion interface" << std::endl;
    std::cout << "  POST /[prefix]/v1/audio/speech            - Text-to-Speech interface" << std::endl; 
    std::cout << "  POST /[prefix]/v1/images/generations      - Image generation interface" << std::endl;
}

// 解析命令行参数
int parseArgs(int argc, char* argv[]) {
    int p = port;
    std::string charset;
    
    if (argc == 1) {
        printHelp();
    }
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printHelp();
            exit(0);
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                try {
                    p = std::stoi(argv[++i]);
                    if (p < 0 || p > 65535) {
                        std::cerr << "Error: Port must be between 0 and 65535" << std::endl;
                        printHelp();
                    }
                } catch (const std::exception&) {
                    std::cerr << "Error: Port must be a number" << std::endl;
                    printHelp();
                }
            } else {
                std::cerr << "Error: Port number is missing" << std::endl;
                printHelp();
            }
        } else if (arg == "-c" || arg == "--charset") {
            if (i + 1 < argc) {
                charset = argv[++i];
                std::transform(charset.begin(), charset.end(), charset.begin(), ::toupper);
                if (charset != "UTF-8" && charset != "GBK") {
                    std::cerr << "Error: Unsupported charset " << charset << std::endl;
                    printHelp();
                }
            } else {
                std::cerr << "Error: Charset name is missing" << std::endl;
                printHelp();
            }
        } else if (arg == "-f" || arg == "--prefix") {
            if (i + 1 < argc) {
                prefix = argv[++i];
                // 允许用户输入前缀时带/或不带/，统一处理
                if (!prefix.empty() && prefix[0] == '/') {
                    prefix = prefix.substr(1);
                }
                if (!prefix.empty() && prefix[prefix.size() - 1] == '/') {
                    prefix = prefix.substr(0, prefix.size() - 1);
                }
            } else {
                std::cerr << "Error: Prefix is missing" << std::endl;
                printHelp();
            }
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            printHelp();
        }
    }
    
    // 处理charset设置（虽然C++版本不需要实际改变输出编码）
    if (!charset.empty()) {
        std::cout << "Charset option: " << charset << " (Note: C++ version uses system default)" << std::endl;
    }
    
    return p;
}


int main(int argc, char* argv[]) {
    try {
#ifdef _WIN32
        // Initialize Winsock once at startup
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Failed to initialize Winsock" << std::endl;
            return 1;
        }
#endif

        // 设置本地化
        std::setlocale(LC_ALL, "zh_CN.UTF-8");
        
        // 首先解析命令行参数
        int p = parseArgs(argc, argv);
        
        // 设置字符集
        std::string cs = "UTF-8"; // 默认UTF-8
        
#ifdef _WIN32
        // Windows系统默认使用GBK
        cs = "GBK";
#endif
        
        std::cout << "Output charset set to: " << cs << std::endl;
        
        // 初始化 curl
        curl_global_init(CURL_GLOBAL_ALL);
        
        // 初始化并缓存一次 JWT（如果可用），以便 ChatProxy 构造函数优先使用缓存的 token。
        // 失败仅记录警告，不阻止服务启动。
        try {
            Utils::init_token_cache();
        } catch (const std::exception& e) {
            std::cerr << "Warning: init_token_cache failed: " << e.what() << std::endl;
        }
        
        // 使用httplib直接尝试绑定端口，简单且跨平台
        bool endpoints_printed = false;  // 标志：确保只打印一次endpoints
        
        for (int port = p; port <= 65535; port++) {
            std::cout << "Trying to start server on port " << port << "..." << std::endl;
            
            // 创建新的服务器对象
            httplib::Server server;
            ChatProxy chat_proxy;
            
            // 设置服务器参数
            server.set_read_timeout(60, 0);    // 60 seconds
            server.set_write_timeout(60, 0);   // 60 seconds
            server.set_idle_interval(0, 100000); // 100ms
            server.set_payload_max_length(1024 * 1024 * 100); // 100MB max
            
            // 处理预检请求的lambda
            auto handleOptions = [](const httplib::Request&, httplib::Response& res) {
                res.set_header("Access-Control-Allow-Origin", "*");
                res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
                res.set_header("Connection", "keep-alive");
                res.status = 204; // No Content
            };
            
            // 设置路径前缀
            std::string prefixPath = prefix.empty() ? "" : "/" + prefix;
            if(prefixPath.empty()) {
                prefixPath="/v1";
            }
            
            // 设置根路径
            server.Get("/", [](const httplib::Request&, httplib::Response& res) {
                std::string response = "<html><head><title>Welcome to API</title></head>"
                    "<body><h1>Welcome to API</h1>"
                    "<p>This API is used to interact with the GitHub Copilot model. "
                    "You can send messages to the model and receive responses.</p>"
                    "</body></html>";
                res.set_header("Content-Type", "text/html; charset=utf-8");
                res.set_content(response, "text/html");
            });
            
            // 设置 OPTIONS 路由
            server.Options(prefixPath + "/chat/completions", handleOptions);
            server.Options(prefixPath + "/models", handleOptions);
            /* images/generations and audio/speech OPTIONS are omitted to match Java Main.java */
            server.Options(prefixPath + "/message", handleOptions);
            
            // 设置 POST/GET 路由
            server.Post(prefixPath + "/chat/completions", [&](const httplib::Request& req, httplib::Response& res) {
                chat_proxy.handle(req, res);
                logResponse(prefixPath + "/chat/completions", res.status, req.version, req.remote_addr, req.remote_port);
            });
            
            server.Get(prefixPath + "/models", [&](const httplib::Request& req, httplib::Response& res) {
                handleModels(req, res);
                logResponse(prefixPath + "/models", res.status, req.version, req.remote_addr, req.remote_port);
            });
            
            /* images/generations and audio/speech endpoints omitted (not present in Java Main.java) */
            
            // 使用bind_to_port和listen_after_bind分离绑定和监听
            // 这样可以检测端口是否真正可用
            if (server.bind_to_port("0.0.0.0", port)) {
                // 成功绑定端口
                ::port = port; // 更新全局端口变量
                std::cout << "Server successfully bound to port " << port << std::endl;
                
                // 仅在第一次成功绑定时打印 Available endpoints（保证只打印一次）
                if (!endpoints_printed) {
                    endpoints_printed = true;
                    std::cout << "Available endpoints:" << std::endl;
                    std::cout << "  GET  " << prefixPath << "/models" << std::endl;
                    std::cout << "  POST " << prefixPath << "/chat/completions" << std::endl;
                }
                
                // 开始监听（阻塞）
                std::cout << "Starting server..." << std::endl;
                if (!server.listen_after_bind()) {
                    std::cerr << "Failed to listen on port " << port << std::endl;
                    continue;
                }
                break; // 服务器运行结束
            } else {
                // 端口被占用，尝试下一个
                std::cout << "Port " << port << " is busy, trying next port..." << std::endl;
                if (port >= 65535) {
                    std::cerr << "No available ports found!" << std::endl;
                    curl_global_cleanup();
#ifdef _WIN32
                    WSACleanup();
#endif
                    return 1;
                }
            }
        }
        
        // 清理
        curl_global_cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error!" << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
}
