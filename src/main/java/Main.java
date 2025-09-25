import java.io.IOException;
import java.io.PrintStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpServer;

public class Main {

    public static int port = 80;
    public static String prefix = ""; // 路径前缀，默认为空
    private static final ExecutorService executor =
            Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

    public static HttpServer createHttpServer(int initialPort) throws IOException {
        int p = initialPort;
        HttpServer server = null;
        while (server == null) {
            try {
                server = HttpServer.create(new InetSocketAddress("0.0.0.0", p), 0);
                System.out.println("Server started on port " + p);
                Main.port = p;
            } catch (BindException e) {
                // 端口冲突，尝试下一个…
                p = (p < 65535) ? p + 1 : p - 1;
                System.err.println("Port conflict, trying " + p);
            }
        }
        return server;
    }

    /**
     * Displays help information for the application
     */
    private static void printHelp() {
        System.out.println("Usage: java -jar GPT4.jar [options]");
        System.out.println("Options:");
        System.out.println("  -h, --help                 Display this help message");
        System.out.println("  -p, --port <number>        Specify the port number (default: 80)");
        System.out.println("  -c, --charset <charset>    Set output charset: UTF-8 or GBK (default depends on OS)");
        System.out.println("  -f, --prefix <prefix>      Set API path prefix, e.g. GPT4 (default: none)");
        System.out.println();
        System.out.println("Supported endpoints:");
        System.out.println("  GET  /[prefix]/v1/models                  - List supported models");
        System.out.println("  POST /[prefix]/v1/chat/completions        - OpenAI Chat/completion interface");
    }

    /**
     * Parse command line arguments
     * @param args Command line arguments
     * @return The port number specified or the default port
     */
    private static int parseArgs(String[] args) {
        int p = port;
        if(args.length==0) {
            printHelp();
        }
        String charset = null;
   
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            switch (arg) {
                case "-h":
                case "--help":
                    printHelp();
                    System.exit(0);
//                    break;
                case "-p":
                case "--port":
                    if (i + 1 < args.length) {
                        try {
                            p = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Error: Port must be a number");
                            printHelp();
//                            System.exit(0);
                        }
                    } else {
                        System.err.println("Error: Port number is missing");
                        printHelp();
//                        System.exit(0);
                    }
                    break;
                case "-c":
                case "--charset":
                    if (i + 1 < args.length) {
                        charset = args[++i].toUpperCase();
                        if (!charset.equals("UTF-8") && !charset.equals("GBK")) {
                            System.err.println("Error: Unsupported charset " + charset);
                            printHelp();
                        }

                    } else {
                        System.err.println("Error: Charset name is missing");
                        printHelp();
                    }

                    break;
                case "-f":
                case "--prefix":
                    if (i + 1 < args.length) {
                        prefix = args[++i];
                        // 允许用户输入前缀时带/或不带/，统一处理
                        if (prefix.startsWith("/")) {
                            prefix = prefix.substring(1);
                        }
                        if (prefix.endsWith("/")) {
                            prefix = prefix.substring(0, prefix.length() - 1);
                        }
                    } else {
                        System.err.println("Error: Prefix is missing");
                        printHelp();
                    }
                    break;
                default:
                    System.err.println("Unknown option: " + arg);
                    printHelp();
            }
        }
        
        if (charset != null) {
            System.setProperty("gpt4.charset", charset);
        }

        return p;
    }

    /**
     * 检测是否在AOT（Ahead-of-Time）编译环境下运行
     * 通常是指GraalVM Native Image或类似技术
     * @return 如果是AOT环境返回true，否则返回false
     */
    private static boolean isRunningInAot() {
        // 方法1：检查GraalVM特定的系统属性
        if (System.getProperty("org.graalvm.nativeimage.imagecode") != null) {
            return true;
        }

        // 方法2：检查native-image特定的类是否存在
        try {
            Class.forName("org.graalvm.nativeimage.ImageInfo");
            return true;
        } catch (ClassNotFoundException e) {
            // 类不存在，可能不是在Native Image环境
        }
        
        // 方法3：检查java.vm.name是否包含"Native Image"
        String vmName = System.getProperty("java.vm.name", "").toLowerCase();
        return vmName.contains("native image");
    }
    
    public static void main(String[] args) throws IOException {
        // 首先解析命令行参数，确保获取到-c参数
        int p = parseArgs(args);
        
        try {
            // 获取charset系统属性（由parseArgs设置）
            String cs = System.getProperty("gpt4.charset");
            
            // 如果未指定charset，根据运行环境和操作系统设置默认值
            if (cs == null) {
                boolean isWindows = System.getProperty("os.name").toLowerCase().contains("windows");
                boolean isAot = isRunningInAot();
                
                // 在AOT编译下，Windows默认GBK，其他系统默认UTF-8
                if (isAot) {
                    cs = isWindows ? "GBK" : "UTF-8";
                    System.out.println("Running in AOT mode, default charset: " + cs);
                } else {
                    // 非AOT环境下，使用系统默认编码
                    cs = System.getProperty("file.encoding", isWindows ? "GBK" : "UTF-8");
                    System.out.println("Running in JVM mode, default charset: " + cs);
                }
                
                System.setProperty("gpt4.charset", cs);
            }
            
            try {
                java.io.OutputStream os = System.out;  // 获取 System.out 的 OutputStream
                PrintStream ps = new PrintStream(os, true, cs);
                System.setOut(ps);  // 设置新的 System.out 输出流
                
                // 同样应用到标准错误输出
                java.io.OutputStream errOs = System.err;
                PrintStream errPs = new PrintStream(errOs, true, cs);
                System.setErr(errPs);
                
                System.out.println("Output charset set to: " + cs);
            } catch (Exception e) {
                System.err.println("Warning: Failed to set charset to " + cs + ". Falling back to system default.");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        HttpServer server = createHttpServer(p);

        // 统一处理前缀，未设置时为""
        String prefixPath = prefix.isEmpty() ? "" : "/" + prefix;
        // 打印监听端口和所有实际监听路径
        System.out.println("Available endpoints:");
        if(prefixPath.isEmpty()) {
            prefixPath="/v1";
        }
        System.out.println("  GET  " + prefixPath + "/models");
        System.out.println("  POST " + prefixPath + "/chat/completions");
        server.createContext(prefixPath + "/models", new ModelsHandler());
        server.createContext(prefixPath + "/chat/completions", new ChatProxy());
        server.setExecutor(executor);
        server.start();
    }
}

