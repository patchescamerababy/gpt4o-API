import Utils.Utils;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.zip.GZIPInputStream;
import org.brotli.dec.BrotliInputStream;

import static Utils.Client.getOkHttpClient;

/**
 * Image generation endpoint (OpenAI-like).
 *
 * Request JSON fields:
 *  - prompt (required)
 *  - size: one of 1024x1024 / 1536x1024 / 1024x1536 (else defaults to 1536x1024)
 *  - model (default gpt-image-1)
 *  - style (default default)
 *  - n (currently ignored downstream, default 1)
 *  - response_format: "b64_json" -> return base64 JSON from upstream; otherwise convert to url.
 */
public class ImageProxy implements HttpHandler {

    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json");
    private static final String IMAGE_SERVICE_URL =
            "https://apieyhfveujcbdhss-21945c360009.herokuapp.com/api/image/generate";
    private static final String APP_TOKEN = "yankundaikishi-one-token-ohojsgcdkchjdbs";
    private static final String DEFAULT_MODEL = "gpt-image-1";

    private static final String SIZE_SQUARE = "1024x1024";
    private static final String SIZE_WIDE   = "1536x1024";
    private static final String SIZE_TALL   = "1024x1536";
    private static final String DEFAULT_SIZE = SIZE_WIDE;

    // JDK 8 兼容写法（不可变集合）
    private static final Set<String> ALLOWED_SIZES = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(SIZE_SQUARE, SIZE_WIDE, SIZE_TALL))
    );

    private static final String DEFAULT_STYLE = "default";

    private final OkHttpClient httpClient = getOkHttpClient();
    private final Executor requestExecutor = Executors.newCachedThreadPool();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Headers responseHeaders = exchange.getResponseHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", "*");
        responseHeaders.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers", "Content-Type, Authorization");

        String method = exchange.getRequestMethod();
        if ("OPTIONS".equalsIgnoreCase(method)) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }
        if (!"POST".equalsIgnoreCase(method)) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        CompletableFuture.runAsync(new Runnable() {
            @Override
            public void run() {
                processRequest(exchange);
            }
        }, requestExecutor);
    }

    private void processRequest(HttpExchange exchange) {
        try (InputStream requestBodyStream = exchange.getRequestBody();
             InputStreamReader isr = new InputStreamReader(requestBodyStream, StandardCharsets.UTF_8);
             BufferedReader br = new BufferedReader(isr)) {

            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            String requestBodyText = sb.toString();

            JSONObject requestJson = new JSONObject(requestBodyText);
            System.out.println("Incoming request:\n" + requestJson.toString(4));

            String prompt = requestJson.optString("prompt", "").trim();
            if (prompt.isEmpty()) {
                sendErrorJson(exchange, 400, "missing prompt");
                return;
            }

            int imageCount = requestJson.optInt("n", 1); // 预留（当前未传递多图）

            String responseFormat = requestJson.optString("response_format", "");
            boolean wantBase64 = "b64_json".equalsIgnoreCase(responseFormat);

            // ---- Size validation ----
            String requestedSize = requestJson.optString("size", DEFAULT_SIZE).trim();
            String finalSize = ALLOWED_SIZES.contains(requestedSize) ? requestedSize : DEFAULT_SIZE;
            int width = Integer.parseInt(finalSize.split("x")[0]);
            int height = Integer.parseInt(finalSize.split("x")[1]);

            String model = requestJson.optString("model", DEFAULT_MODEL);
            String style = requestJson.optString("style", DEFAULT_STYLE);

            // Build downstream generation request
            JSONObject generationRequestJson = new JSONObject();
            generationRequestJson.put("model", DEFAULT_MODEL);
            generationRequestJson.put("prompt", prompt);
            generationRequestJson.put("quality", "high");
//            generationRequestJson.put("moderation", "low");
            generationRequestJson.put("size", SIZE_TALL);
            generationRequestJson.put("count", 1);

            System.out.println("Generation request:\n" + generationRequestJson.toString(4));

            // 调用上游服务生成图片，传入生成请求JSON以及是否需要base64编码的信息
            String result = postToImageService(generationRequestJson.toString(), wantBase64);
            
            if (result == null) {
                sendErrorJson(exchange, 502, "image service no response");
                return;
            }
            
            // 检查result是否是JSON格式
            boolean isJson = result.trim().startsWith("{") || result.trim().startsWith("[");
            
            if (wantBase64) {
                if (isJson) {
                    // 如果是JSON格式，检查是否是完整的base64编码URL
                    try {
                        // 尝试解码，验证是否为有效的base64
                        Base64.getDecoder().decode(result);
                        
                        // 构建符合OpenAI格式的响应
                        JSONObject openAiStyleResponseJson = new JSONObject();
                        openAiStyleResponseJson.put("created", Instant.now().getEpochSecond());
                        
                        JSONArray dataArray = new JSONArray();
                        dataArray.put(new JSONObject().put("b64_json", result));
                        openAiStyleResponseJson.put("data", dataArray);
                        
                        writeJson(exchange, 200, openAiStyleResponseJson.toString());
                    } catch (IllegalArgumentException e) {
                        // 不是有效的base64，直接返回原始响应
                        writeJson(exchange, 200, result);
                    }
                } else {
                    // 不是JSON格式，可能是直接的base64字符串
                    JSONObject openAiStyleResponseJson = new JSONObject();
                    openAiStyleResponseJson.put("created", Instant.now().getEpochSecond());
                    
                    JSONArray dataArray = new JSONArray();
                    dataArray.put(new JSONObject().put("b64_json", result));
                    openAiStyleResponseJson.put("data", dataArray);
                    
                    writeJson(exchange, 200, openAiStyleResponseJson.toString());
                }
                return;
            } else {
                // 用户要求URL格式
                if (result.startsWith("http")) {
                    // 结果是URL，构建OpenAI格式的响应
                    JSONObject openAiStyleResponseJson = new JSONObject();
                    openAiStyleResponseJson.put("created", Instant.now().getEpochSecond());
                    
                    JSONArray dataArray = new JSONArray();
                    dataArray.put(new JSONObject().put("url", result));
                    openAiStyleResponseJson.put("data", dataArray);
                    
                    writeJson(exchange, 200, openAiStyleResponseJson.toString());
                } else if (isJson) {
                    // 尝试从JSON中提取URL
                    try {
                        JSONObject jsonResponse = new JSONObject(result);
                        // 检查是否包含images数组
                        if (jsonResponse.has("images") && jsonResponse.getJSONArray("images").length() > 0) {
                            JSONObject imageObject = jsonResponse.getJSONArray("images").getJSONObject(0);
                            String imageUrl = imageObject.getString("url");
                            
                            // 构建OpenAI格式的响应
                            JSONObject openAiStyleResponseJson = new JSONObject();
                            openAiStyleResponseJson.put("created", Instant.now().getEpochSecond());
                            
                            JSONArray dataArray = new JSONArray();
                            dataArray.put(new JSONObject().put("url", imageUrl));
                            openAiStyleResponseJson.put("data", dataArray);
                            
                            writeJson(exchange, 200, openAiStyleResponseJson.toString());
                        } else {
                            // 原始JSON不包含预期的结构，直接返回
                            writeJson(exchange, 200, result);
                        }
                    } catch (Exception e) {
                        // JSON解析失败，直接返回原始响应
                        writeJson(exchange, 200, result);
                    }
                } else {
                    // 不是URL也不是JSON，返回错误
                    sendErrorJson(exchange, 502, result);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            sendErrorJson(exchange, 500, e.getMessage());
        }
    }

    /** 
     * POST to upstream image service
     * @param requestJsonString 图片生成请求的JSON字符串
     * @param wantBase64 是否需要返回base64编码的URL
     * @return 如果wantBase64为true，返回base64编码的URL；否则返回直接URL或原始响应
     */
    private String postToImageService(String requestJsonString, boolean wantBase64) {
//        Request request = new Request.Builder()
//                .url(IMAGE_SERVICE_URL)
//                .post(RequestBody.create(
//                        requestJsonString.getBytes(StandardCharsets.UTF_8),
//                        MediaType.parse("application/json; charset=utf-8")))
//                .addHeader("x-my-app-token", APP_TOKEN)
//                .addHeader("User-Agent", "aidictionary/10.9 (jp.techacademy.masaki.matsushita.aidictionary; build:32.3; iOS 18.1.1) Alamofire/5.9.1")
//                .addHeader("Accept", "*/*")
//                .addHeader("Connection", "Keep-Alive")
//                .addHeader("Accept-Language", "zh-Hans-HK;q=1.0, ja-HK;q=0.9, zh-Hant-TW;q=0.8, en-HK;q=0.7, wuu-Hans-HK;q=0.6")
//                .addHeader("Content-Type", "application/json")
//                .addHeader("Accept-Encoding", "br;q=1.0, gzip;q=0.9, deflate;q=0.8")
//                .build();
        Request request = new Request.Builder()
                .url("https://chat.alma.tatar/api/v3/chat/image/generate")
                .post(RequestBody.create(
                        requestJsonString.getBytes(StandardCharsets.UTF_8),
                        MediaType.parse("application/json; charset=utf-8")))
                .addHeader("x-api-key", "prod_tg4Jq28JlEwj2EXIsmOjHr6AN76mUJ")
                .addHeader("User-Agent", "ScarletAI/7 CFNetwork/3855.100.1 Darwin/25.0.0")
                .addHeader("Accept", "application/json, text/plain, */*")
                .addHeader("Connection", "Keep-Alive")
                .addHeader("Accept-Language", "zh-CN,zh-Hans;q=0.9")
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept-Encoding", "gzip, deflate, br")
                .build();
        Response response = null;
        try {
            response = httpClient.newCall(request).execute();
            if (!response.isSuccessful()) {
                System.out.println("Image service error: " + response.code() + " " + response.message());
            }
            if (response.body() == null) {
                return null;
            }
            
            // 获取响应内容类型和编码方式
            String contentEncoding = response.header("Content-Encoding", "");
            byte[] responseBytes = response.body().bytes();
            String responseBody;
            
            // 根据不同的压缩类型进行解压
            if ("gzip".equalsIgnoreCase(contentEncoding)) {
                // 处理 gzip 压缩
                try (GZIPInputStream gzipIn = new GZIPInputStream(new ByteArrayInputStream(responseBytes));
                     InputStreamReader isr = new InputStreamReader(gzipIn, StandardCharsets.UTF_8);
                     BufferedReader br = new BufferedReader(isr)) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line);
                    }
                    responseBody = sb.toString();
                }
            } else if ("deflate".equalsIgnoreCase(contentEncoding)) {
                // 处理 deflate 压缩
                try (java.util.zip.InflaterInputStream inflaterIn = new java.util.zip.InflaterInputStream(
                        new ByteArrayInputStream(responseBytes));
                     InputStreamReader isr = new InputStreamReader(inflaterIn, StandardCharsets.UTF_8);
                     BufferedReader br = new BufferedReader(isr)) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line);
                    }
                    responseBody = sb.toString();
                }
            } else if ("br".equalsIgnoreCase(contentEncoding)) {
                // 处理 brotli 压缩
                try (BrotliInputStream brIn = new BrotliInputStream(new ByteArrayInputStream(responseBytes));
                     InputStreamReader isr = new InputStreamReader(brIn, StandardCharsets.UTF_8);
                     BufferedReader br = new BufferedReader(isr)) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line);
                    }
                    responseBody = sb.toString();
                }
            } else {
                // 无压缩或未知压缩类型，直接转换为字符串
                responseBody = new String(responseBytes, StandardCharsets.UTF_8);
            }
            
            // 解析JSON响应
            JSONObject jsonResponse = new JSONObject(responseBody);
            
            // 检查是否包含images数组
            if (jsonResponse.has("images") && jsonResponse.getJSONArray("images").length() > 0) {
                JSONObject imageObject = jsonResponse.getJSONArray("images").getJSONObject(0);
                String imageUrl = imageObject.getString("url");
                
                // 使用传入的wantBase64参数决定是否需要下载图片并进行base64编码
                if (wantBase64) {
                    try {
                        // 使用带重试的下载方法
                        String dataUri = Utils.downloadToDataUriWithRetry(
                            imageUrl,      // 图片URL
                            3,             // 最大重试3次
                            100,           // 初始退避100ms
                            1000,          // 单次退避上限1000ms
                            () -> true     // 不设置时间预算限制
                        );
                        
                        // 提取base64部分（去掉"data:image/xxx;base64,"前缀）
                        String base64Data = dataUri.substring(dataUri.indexOf("base64,") + 7);
                        // 返回base64编码后的图片数据
                        return base64Data;
                    } catch (Exception e) {
                        System.out.println("Error downloading and encoding image: " + e.getMessage());
                        e.printStackTrace();
                        // 下载失败时返回错误信息
                        return "Error downloading image: " + e.getMessage();
                    }
                } else {
                    // 直接返回URL
                    return imageUrl;
                }
            } else {
                // 返回原始响应，让调用方处理
                return responseBody;
            }
        } catch (IOException e) {
            System.out.println("Image service IO error: " + e.getMessage());
            return null;
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    private void sendErrorJson(HttpExchange exchange, int statusCode, String message) {
        try {
            JSONObject err = new JSONObject().put("error", message);
            writeJson(exchange, statusCode, err.toString());
        } catch (Exception ignored) {}
    }

    private void writeJson(HttpExchange exchange, int statusCode, String jsonString) throws IOException {
        byte[] responseBytes = jsonString.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
