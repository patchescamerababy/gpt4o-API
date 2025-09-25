package Utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import org.json.JSONArray;
import org.json.JSONObject;

import com.sun.net.httpserver.HttpExchange;

import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class Utils{
    public static void sendError(HttpExchange exchange, String message, int HTTP_code) {
        try {
            JSONObject error = new JSONObject();
            error.put("error", message);
            byte[] bytes = error.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(HTTP_code, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * 带重试的下载：下载图片并返回 data URI。
     * - maxRetries: 最大重试次数
     * - initialBackoffMs: 初始退避
     * - perAttemptDelayCeilMs: 单次失败后退避上限
     * - overallTimeBudgetOk: 整体时间预算检测（返回 false 则终止）
     */
    public static String downloadToDataUriWithRetry(
            String url,
            int maxRetries,
            long initialBackoffMs,
            long perAttemptDelayCeilMs,
            Callable<Boolean> overallTimeBudgetOk
    ) throws Exception {

        long backoff = initialBackoffMs;
        int attempt = 0;

        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

        try {
            while (true) {
                // 检查整体时间预算
                if (overallTimeBudgetOk != null && !overallTimeBudgetOk.call()) {
                    throw new RuntimeException("下载超出整体时间预算");
                }

                try {
                    return downloadOnceToDataUri(url); // 成功直接返回
                } catch (Exception e) {
                    attempt++;
                    if (attempt > maxRetries) {
                        throw new RuntimeException("多次重试仍失败: " + e.getMessage(), e);
                    }
                    // 指数退避 + 抖动
                    long delay = Math.min(backoff, perAttemptDelayCeilMs);
                    delay += (long) (Math.random() * 250); // 抖动

                    // 使用 ScheduledExecutorService 代替 Thread.sleep
                    Future<?> future = scheduler.schedule(() -> {}, delay, TimeUnit.MILLISECONDS);

                    try {
                        future.get(); // 等待完成
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt(); // 保持中断状态
                        throw new RuntimeException("线程中断", ie);
                    } catch (ExecutionException ee) {
                        throw new RuntimeException("调度失败", ee);
                    }

                    backoff = Math.min(backoff * 2, perAttemptDelayCeilMs);
                }
            }
        } finally {
            scheduler.shutdownNow();
        }
    }

    /** 单次下载并转为 data URI */
    public static String downloadOnceToDataUri(String imageURL) throws IOException {
        Request imageRequest = new Request.Builder().url(imageURL).build();
        try (Response imageResponse = Client.getOkHttpClient().newCall(imageRequest).execute()) {
            if (!imageResponse.isSuccessful() || imageResponse.body() == null) {
                throw new IOException("HTTP " + imageResponse.code());
            }
            byte[] imageBytes = imageResponse.body().bytes();

            String contentType = imageResponse.header("Content-Type");
            if (contentType == null || !contentType.startsWith("image/")) {
                // 尝试从 URL 后缀猜测
                contentType = guessImageContentTypeFromUrl(imageURL);
            }
            if (contentType == null || !contentType.startsWith("image/")) {
                contentType = "image/png";
            }

            String base64Image = Base64.getEncoder().encodeToString(imageBytes);
            return "data:" + contentType + ";base64," + base64Image;
        }
    }

    /** 简单从 URL 后缀猜测图片类型 */
    public static String guessImageContentTypeFromUrl(String url) {
        String u = url.toLowerCase(Locale.ROOT);
        if (u.endsWith(".png")) return "image/png";
        if (u.endsWith(".jpg") || u.endsWith(".jpeg")) return "image/jpeg";
        if (u.endsWith(".gif")) return "image/gif";
        if (u.endsWith(".webp")) return "image/webp";
        if (u.endsWith(".bmp")) return "image/bmp";
        if (u.endsWith(".tif") || u.endsWith(".tiff")) return "image/tiff";
        return null;
    }

    
    /**
     * 构建OpenAI格式的SSE响应块，始终包含usage信息
     * @param deltaContent 当前块的内容
     * @param model 模型名称
     * @param convoId 会话ID
     * @param isLastChunk 是否是最后一个块
     * @param currentChunkTokens 当前块的token数量
     * @param promptTokens 提示tokens数量
     * @param accumulatedCompletionTokens 累计的完成tokens数量
     * @return 格式化的SSE响应块
     */
    public static String buildOpenAISSEChunk(String deltaContent, String model, String convoId, boolean isLastChunk, 
                                            int currentChunkTokens, int promptTokens, int accumulatedCompletionTokens) {
        JSONObject delta = new JSONObject().put("content", deltaContent);

        JSONObject choiceObj = new JSONObject()
                .put("index", 0)
                .put("delta", delta)
                .put("finish_reason", isLastChunk ? "stop" : JSONObject.NULL);

        JSONObject response = new JSONObject()
                .put("id", convoId != null ? convoId : "")
                .put("created", Instant.now().getEpochSecond())
                .put("model", model)
                .put("system_fingerprint", "fp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12))
                .put("choices", new JSONArray().put(choiceObj));
        
        // 添加token计数
        if (currentChunkTokens > 0) {
            int totalTokens = promptTokens + accumulatedCompletionTokens;
            response.put("usage", new JSONObject()
                    .put("completion_tokens", totalTokens) // 当前累计的总completion tokens
                    .put("prompt_tokens", promptTokens)
                    .put("total_tokens", totalTokens)); // total_tokens是累计的总数
        }

        return "data: " + response.toString() + "\n\n";
    }

    public static Request buildRequest(String path, String JWT, String body) {
        return new Request.Builder()
                .url("https://python-app-qjk4mlqqha-uc.a.run.app" + path)

                .addHeader("x-api-key", "07D76661F-9337-462F-8645-D8866290F8D8-AI")
                .addHeader("Authorization", JWT)
                .addHeader("User-Agent", "AIGE/2.5.0 (com.botai.chat; build:192; iOS 18.1.1) Alamofire/5.9.1")
                .addHeader("Accept","application/json")
                .addHeader("Accept-Language","zh-Hans-HK;q=1.0, ja-HK;q=0.9, zh-Hant-TW;q=0.8, en-HK;q=0.7, wuu-Hans-HK;q=0.6")
                .addHeader("Content-Type", "application/json; charset=UTF-8")
                .post(RequestBody.create(body, MediaType.get("application/json; charset=utf-8")))
                .build();
    }

    public static JSONObject getToken(OkHttpClient client) {
        try {

            RequestBody body = RequestBody.create(
                    "", MediaType.parse("application/json"));

            Request req = new Request.Builder()
                    .url("https://python-app-qjk4mlqqha-uc.a.run.app/token")
                    .post(body)
                    .addHeader("User-Agent",
                            "AIGE/192 CFNetwork/1568.200.51 Darwin/24.1.0")
                    .addHeader("x-api-key", "07D76661F-9337-462F-8645-D8866290F8D8-AI")
                    .addHeader("Accept", "*/*")
                    .addHeader("Accept-Language", "zh-CN,zh-Hans;q=0.9")
                    .addHeader("Accept-Encoding", "gzip, deflate, br")
                    .addHeader("Connection", "keep-alive")
                    .build();

            try (Response resp = client.newCall(req).execute()) {
                if (!resp.isSuccessful()) {
                    throw new IOException("token request failed: " + resp.code());
                }

                InputStream in = null;
                if (resp.body() != null) {
                    in = resp.body().byteStream();
                }
                if ("gzip".equalsIgnoreCase(resp.header("Content-Encoding"))) {
                    if (in != null) {
                        in = new GZIPInputStream(in);
                    }
                }

                String tokenJson = null;
                if (in != null) {
                    tokenJson = new BufferedReader(
                            new InputStreamReader(in, StandardCharsets.UTF_8))
                            .lines()
                            .collect(java.util.stream.Collectors.joining());
                }
                JSONObject tokenJsonObject = null;
                if (tokenJson != null) {
                    tokenJsonObject = new JSONObject(tokenJson);
                }
                return tokenJsonObject;

            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
