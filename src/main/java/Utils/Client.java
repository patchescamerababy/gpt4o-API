package Utils;

import okhttp3.OkHttpClient;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

public class Client {

    public static OkHttpClient createOkHttpClient() {
        try {
            // 创建一个不验证证书的 TrustManager
            final X509TrustManager trustAllCertificates = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // 不做任何检查
                }
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // 不做任何检查
                }
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };

            // 创建 SSLContext，使用我们的 TrustManager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustAllCertificates}, null);
            // 创建 OkHttpClient
            OkHttpClient client = new OkHttpClient.Builder()
                    // 设置 SSL
                    .sslSocketFactory(sslContext.getSocketFactory(), trustAllCertificates)
                    .hostnameVerifier((hostname, session) -> true) // 不验证主机名
                    .connectTimeout(36000, TimeUnit.SECONDS)  // 连接超时
                    .readTimeout(36000, TimeUnit.SECONDS)     // 读取超时
                    .writeTimeout(36000, TimeUnit.SECONDS)    // 写入超时
                    .proxy(getSystemProxy())  // 设置系统代理
                    .build();
            return client;
        } catch (Exception e) {
            throw new RuntimeException("OkHttpClient 初始化失败", e);
        }
    }

    public static OkHttpClient getOkHttpClient() {
        return createOkHttpClient();
    }
    /**
     * 调用 reg.exe 读取注册表中某个键值（以字符串形式返回）。
     * 兼容 Windows XP 及以上。
     *
     * @param hive  根键名："HKCU", "HKLM" 等
     * @param path  子路径，例如 "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
     * @param key   值名称，例如 "ProxyEnable" 或 "ProxyServer"
     * @return      如果存在则返回值（例如 "0x1"、"proxy.example.com:8080" 等），否则返回 null
     */
    public static String readRegistry(String hive, String path, String key) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("reg", "query",
                hive + "\\" + path,
                "/v", key);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), "GBK"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.startsWith(key)) {
                    // 按空白分割，最后一段即为值
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 3) {
                        return parts[parts.length - 1];
                    }
                }
            }
        }
        return null;
    }

    /**
     * 解析代理字符串，支持：
     *  - socks=host:port 或 socks5=host:port
     *  - http=host:port、https=host:port
     *  - 纯 host:port（默认 HTTP，端口若缺省则用 80）
     *
     * @param proxyStr  原始代理配置字符串
     * @return          java.net.Proxy 对象（Type 为 HTTP 或 SOCKS）
     */
    private static Proxy parseProxy(String proxyStr) {
        String s = proxyStr.trim();

        // 去掉协议前缀（http://、https://、socks://、socks5://）
        s = s.replaceFirst("(?i)^(http|https|socks5?)://", "");

        // 去掉用户认证信息
        int at = s.lastIndexOf('@');
        if (at >= 0) {
            s = s.substring(at + 1);
        }

        // 默认 HTTP
        Proxy.Type type = Proxy.Type.HTTP;

        // 检查多协议条目形式：socks=...;http=...;...
        if (s.contains("=") && s.contains(";")) {
            // 以分号拆分，优先找 socks= 或 socks5=
            for (String entry : s.split(";")) {
                String e = entry.trim().toLowerCase();
                if (e.startsWith("socks5=") || e.startsWith("socks=")) {
                    type = Proxy.Type.SOCKS;
                    s = entry.substring(entry.indexOf('=') + 1);
                    break;
                } else if (e.startsWith("http=")) {
                    // 后续若无 socks，才处理 http=
                    s = entry.substring(entry.indexOf('=') + 1);
                    type = Proxy.Type.HTTP;
                }
            }
        } else {
            // 单一条目且以 socks= 或 socks5= 开头
            String low = s.toLowerCase();
            if (low.startsWith("socks5=") || low.startsWith("socks=")) {
                type = Proxy.Type.SOCKS;
                s = s.substring(s.indexOf('=') + 1);
            }
        }

        // 拆分 host:port
        String host;
        int port = (type == Proxy.Type.SOCKS ? 1080 : 80);
        if (s.contains(":")) {
            String[] hp = s.split(":", 2);
            host = hp[0];
            try {
                port = Integer.parseInt(hp[1].replaceAll("/.*$", ""));
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("无效的端口号: " + hp[1], ex);
            }
        } else {
            host = s;
        }

        return new Proxy(type, new InetSocketAddress(host, port));
    }

    /**
     * 获取 Windows 上的系统代理（HTTP / HTTPS / SOCKS5）。
     * 优先级：
     *   1. Java 系统属性 http.proxyHost/http.proxyPort
     *   2. 环境变量 HTTP_PROXY
     *   3. 注册表：ProxyEnable + ProxyServer
     */
    public static Proxy getWindowsProxy() {
        // 1. Java 系统属性
        String propHost = System.getProperty("http.proxyHost");
        String propPort = System.getProperty("http.proxyPort");
        if (propHost != null && propPort != null) {
            try {
                int port = Integer.parseInt(propPort);
                if (port > 0 && port <= 65535) {
                    return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(propHost, port));
                }
            } catch (NumberFormatException ignored) { }
        }

        // 2. 环境变量
        String env = System.getenv("HTTP_PROXY");
        if (env != null && !env.isEmpty()) {
            return parseProxy(env);
        }

        // 3. 注册表
        String hive = "HKCU";
        String path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        try {
            String enable = readRegistry(hive, path, "ProxyEnable");
            if ("0x1".equalsIgnoreCase(enable) || "1".equals(enable)) {
                String server = readRegistry(hive, path, "ProxyServer");
                if (server != null && !server.isEmpty()) {
                    System.out.println("Detected system proxy from Registry: " + server);
                    return parseProxy(server);
                }
            }
        } catch (IOException e) {
            System.err.println("Read Registry Failed: " + e.getMessage());
        }
        System.err.println("Warning: No system proxy detected");
        return Proxy.NO_PROXY;
    }

    /**
     * 获取 Unix-like (Linux/macOS) 系统代理（HTTP / HTTPS / SOCKS5）。
     * 检查环境变量（优先级由上至下）：
     *   socks5_proxy, SOCKS5_PROXY,
     *   socks_proxy,  SOCKS_PROXY,
     *   all_proxy,    ALL_PROXY,
     *   https_proxy,  HTTPS_PROXY,
     *   http_proxy,   HTTP_PROXY
     */
    public static Proxy getUnixProxy() {
        String[] vars = {
                "socks5_proxy", "SOCKS5_PROXY",
                "socks_proxy",  "SOCKS_PROXY",
                "all_proxy",    "ALL_PROXY",
                "https_proxy",  "HTTPS_PROXY",
                "http_proxy",   "HTTP_PROXY"
        };
        for (String env : vars) {
            String val = System.getenv(env);
            if (val != null && !val.isEmpty()) {
                return parseProxy(val);
            }
        }
        System.err.println("Warning: No system proxy detected");
        return Proxy.NO_PROXY;
    }

    /**
     * 检测当前操作系统并返回对应的系统代理设置。
     */
    public static Proxy getSystemProxy() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            return getWindowsProxy();
        } else {
            return getUnixProxy();
        }
    }
}
