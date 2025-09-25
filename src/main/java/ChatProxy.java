import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.json.JSONArray;
import org.json.JSONObject;

import com.knuddels.jtokkit.Encodings;
import com.knuddels.jtokkit.api.Encoding;
import com.knuddels.jtokkit.api.EncodingRegistry;
import com.knuddels.jtokkit.api.EncodingType;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import Utils.Client;
import static Utils.Utils.buildRequest;
import static Utils.Utils.downloadToDataUriWithRetry;
import static Utils.Utils.getToken;
import static Utils.Utils.sendError;
import okhttp3.Request;
import okhttp3.Response;

public class ChatProxy implements HttpHandler {

    private static final Encoding ENCODING;

    static {
        EncodingRegistry reg = Encodings.newDefaultEncodingRegistry();
        ENCODING = reg.getEncoding(EncodingType.CL100K_BASE);
    }


    // 当前 JWT 及其过期时间（秒级时间戳）
    private String token;
    private long tokenExp;

    /* ---------- 线程池 ---------- */
    private final ExecutorService executor = Executors.newFixedThreadPool(
            Runtime.getRuntime().availableProcessors()
    );

    /**
     * 从服务端获取新的 JWT，解析 payload 中的 exp，并更新 token/tokenExp
     */
    private void refreshToken() {
        JSONObject bearer = getToken(Client.getOkHttpClient());
        if (bearer == null) {
            throw new IllegalStateException("无法获取新的 Token");
        }
        String newToken = bearer.optString("access_token");
        if (newToken == null || newToken.isEmpty()) {
            throw new IllegalStateException("返回的 access_token 为空");
        }

        // 解析 JWT 的第二段（payload），Base64URL 解码后获取 exp
        try {
            String[] parts = newToken.split("\\.");
            String payloadJson = new String(
                    Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8
            );
            JSONObject payload = new JSONObject(payloadJson);
            long exp = payload.optLong("exp", 0);
            if (exp == 0) {
                throw new IllegalStateException("JWT payload 中未包含 exp");
            }
            this.token = newToken;
            this.tokenExp = exp;

        } catch (Exception e) {
            throw new RuntimeException("解析 JWT 过期时间失败", e);
        }
    }

    public ChatProxy() {
        // 类实例化时，立即获取并解析一次 token
        refreshToken();
    }

    /**
     * 确保当前 token 有效：如果已过期则重新获取
     */
    private synchronized void ensureValidToken() {
        long now = Instant.now().getEpochSecond();

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");

        LocalDateTime expirationTime = LocalDateTime.ofInstant(Instant.ofEpochSecond(tokenExp), ZoneId.systemDefault());
        String formattedExpiration = expirationTime.format(formatter);

        LocalDateTime currentTime = LocalDateTime.ofInstant(Instant.ofEpochSecond(now), ZoneId.systemDefault());
        String formattedCurrent = currentTime.format(formatter);

        int remainingSeconds = (int) (tokenExp - now);
        int minutes = remainingSeconds / 60;
        int seconds = remainingSeconds % 60;
        System.out.println("\n  Current  time: " + formattedCurrent);
        System.out.println("Expiration time: " + formattedExpiration);
        System.out.println("Remaining: " + minutes + " minutes " + seconds + " seconds");

        if (token == null || now >= tokenExp) {
            refreshToken();
        }
    }


    /* ---------- 处理入口 ---------- */
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        ensureValidToken();
        /* --- CORS 与预检 --- */
        Headers headers = exchange.getResponseHeaders();
        headers.add("Access-Control-Allow-Origin", "*");
        headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization");

        String method = exchange.getRequestMethod().toUpperCase();
        if ("OPTIONS".equals(method)) {        // 预检
            exchange.sendResponseHeaders(204, -1);
            return;
        }
        if ("GET".equals(method)) {
            // 返回欢迎页面
            String response = "<html><head><title>欢迎使用API</title></head><body><h1>欢迎使用API</h1><p>此 API 用于与 gpt-4o 模型交互。您可以发送消息给模型并接收响应。</p></body></html>";

            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, response.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes(StandardCharsets.UTF_8));
            }
            return;
        }
        if (!"POST".equals(method)) {          // 其它方法
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try (InputStream is = exchange.getRequestBody()) {
            /* 1. 解析请求体 */
            String reqBody = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))
                    .lines().reduce("", (acc, line) -> acc + line);
            if (!reqBody.startsWith("{")) {
                System.err.println(reqBody);
                sendError(exchange, "Not JSON", 503);
                return;
            }
            JSONObject reqJson = new JSONObject(reqBody);
            JSONArray messages = reqJson.getJSONArray("messages");
            String modelName = reqJson.optString("model", "gpt-4o");
            boolean isStream = reqJson.optBoolean("stream", false);

            /* 2. 构造上游请求 */
            // 首先，复制原始请求的所有字段
            JSONObject requestJson = new JSONObject(reqJson.toString());
            
            boolean needUsageChunk = false;
            JSONObject stream_options = reqJson.optJSONObject("stream_options");
            if (stream_options != null) {
                needUsageChunk = stream_options.optBoolean("include_usage", false);
            }
            
            // 只处理 messages 数组，保留其他所有字段
            if (messages != null) {
                JSONArray newMessages = new JSONArray();

                // —— 并发下载所有需要转成 data: 的图片（多张图并发 + 重试，直到全部成功或超时）—— //
                List<CompletableFuture<Void>> imageTasks = new ArrayList<>();
                final long OVERALL_DEADLINE_MS = 120_000L; // 整体截止：120 秒，防止无限等待
                final long startAt = System.currentTimeMillis();

                for (int i = 0; i < messages.length(); i++) {
                    JSONObject message = messages.getJSONObject(i);

                    // 扫描图片，给每个非 data: URL 建立一个异步下载任务
                    if (message.has("content") && message.get("content") instanceof JSONArray) {
                        JSONArray contentArray = message.getJSONArray("content");
                        for (int j = 0; j < contentArray.length(); j++) {
                            JSONObject contentItem = contentArray.optJSONObject(j);
                            if (contentItem == null) continue;

                            if (!"image_url".equals(contentItem.optString("type"))) continue;
                            JSONObject imageUrlObj = contentItem.optJSONObject("image_url");
                            if (imageUrlObj == null) continue;

                            String imageURL = imageUrlObj.optString("url", "");
                            if (imageURL == null || imageURL.isEmpty() || imageURL.startsWith("data:image/")) {
                                continue; // 已是 data: 或空，无需下载
                            }

                            // 对每个图片并发下载 + 重试，成功后写回 data URI
                            CompletableFuture<Void> task = CompletableFuture.runAsync(() -> {
                                try {
                                    String dataUri = downloadToDataUriWithRetry(
                                            imageURL,
                                            8,          // 最大重试次数
                                            200L,       // 初始退避
                                            5_000L,     // 退避上限
                                            () -> System.currentTimeMillis() - startAt < OVERALL_DEADLINE_MS
                                    );
                                    synchronized (imageUrlObj) {
                                        imageUrlObj.put("url", dataUri);
                                    }
                                } catch (Exception e) {
                                    throw new CompletionException(e);
                                }
                            }, executor);

                            imageTasks.add(task);
                        }
                    }

                    // 规范化消息（合并纯 text 段为单字符串）
                    JSONObject normalized = normalizeMessage(message);
                    newMessages.put(normalized);
                }

                // 等待所有图片任务完成
                if (!imageTasks.isEmpty()) {
                    CompletableFuture<Void> all = CompletableFuture.allOf(imageTasks.toArray(new CompletableFuture[0]));
                    try {
                        long remaining = OVERALL_DEADLINE_MS - (System.currentTimeMillis() - startAt);
                        if (remaining > 0) {
                            all.get(remaining, java.util.concurrent.TimeUnit.MILLISECONDS);
                        } else {
                            throw new RuntimeException("图片下载超时：超过整体截止时间");
                        }
                    } catch (Exception e) {
                        throw new RuntimeException("图片下载失败：" + e.getMessage(), e);
                    }
                }

                // —— 关键规则：只要"当前请求中最后一条消息含图片"，就在末尾追加空的 user —— //
                JSONObject lastMsg = messages.getJSONObject(messages.length() - 1);
                boolean lastHasImage = hasAnyImageUrl(lastMsg); // 只要含 image_url（无论是否同时有文本）即视为"图片消息"
                if (lastHasImage) {
                    JSONObject placeholder = new JSONObject();
                    placeholder.put("role", "user");
                    placeholder.put("content", "");
                    newMessages.put(placeholder);
                }

                // 仅更新 messages 字段，保留其他所有字段
                requestJson.put("messages", newMessages);
            } else {
                // 兜底
                requestJson.put("messages", new JSONArray());
            }

            Request upstreamReq = buildRequest("/ai/chat/completion", token, requestJson.toString());

            /* 3. 调用上游并分流处理 */
            if (isStream) {
                /* -- 流式返回 -- */
                handleStreamResponse(exchange, upstreamReq, needUsageChunk);   // <── 传参
            } else {
                /* -- 非流式返回 -- */
                handleNormalResponse(exchange, upstreamReq);
            }

        } catch (Exception e) {
            e.printStackTrace();
            Utils.Utils.sendError(exchange, "内部服务器错误: " + e.getMessage(), 500);
        }
    }


    // 是否含任意 image_url（无论是否同时包含文本，都算“图片消息”）
    private boolean hasAnyImageUrl(JSONObject msg) {
        Object c = msg.opt("content");
        if (!(c instanceof JSONArray)) return false;
        JSONArray arr = (JSONArray) c;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject it = arr.optJSONObject(i);
            if (it == null) continue;
            if ("image_url".equals(it.optString("type")) && it.has("image_url")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 规范化一条 message：
     * 1. 如果 content 是数组且全部是 type="text"，将它们合并为一个扁平的 content 字符串。
     * 2. 否则保留原样（包括 image_url 处理之前/之后）。
     */
    private JSONObject normalizeMessage(JSONObject message) {
        // 克隆一份避免改原始（可选）
        JSONObject result = new JSONObject(message.toString());

        if (result.has("content") && result.get("content") instanceof JSONArray) {
            JSONArray contentArray = result.getJSONArray("content");

            // 检查是否全是 text 类型
            boolean allText = true;
            StringBuilder combined = new StringBuilder();
            for (int i = 0; i < contentArray.length(); i++) {
                JSONObject item = contentArray.optJSONObject(i);
                if (item == null) {
                    allText = false;
                    break;
                }
                String type = item.optString("type", "");
                String text = item.optString("text", null);
                if (!"text".equals(type) || text == null) {
                    allText = false;
                    break;
                }
                if (i > 0) {
                    combined.append("\n"); // 多段文本用换行分隔（视需求可改）
                }
                combined.append(text);
            }

            if (allText) {
                // 扁平化：变成 { role: ..., content: "..." }
                JSONObject flat = new JSONObject();
                flat.put("role", result.optString("role"));
                flat.put("content", combined.toString());
                return flat;
            }
        }

        // 不是全 text 数组，原样返回（但注意 image_url 后续可能插入空 message）
        return result;
    }

    /**
     * @param needUsageChunk 当 true 时，尾部额外发 usage 统计块；否则只发 [DONE]
     */
    private void handleStreamResponse(HttpExchange exchange,
                                      Request request,
                                      boolean needUsageChunk) throws IOException {

        // 先计算promptTokens
        int promptTokens = 0;
        try {
            if (request.body() != null) {
                okio.Buffer reqBuf = new okio.Buffer();
                request.body().writeTo(reqBuf);
                String reqJson = reqBuf.readUtf8();

                org.json.JSONObject root = new org.json.JSONObject(reqJson);
                org.json.JSONArray msgs = root.optJSONArray("messages");
                if (msgs != null) {
                    StringBuilder promptTxt = new StringBuilder();
                    for (int i = 0; i < msgs.length(); i++) {
                        Object content = msgs.getJSONObject(i).opt("content");
                        if (content instanceof String) {
                            promptTxt.append((String) content).append('\n');
                        } else if (content instanceof org.json.JSONArray) {
                            org.json.JSONArray arr = (org.json.JSONArray) content;
                            for (int j = 0; j < arr.length(); j++) {
                                org.json.JSONObject part = arr.optJSONObject(j);
                                if (part != null && "text".equals(part.optString("type"))) {
                                    promptTxt.append(part.optString("text")).append('\n');
                                }
                            }
                        }
                    }
                    promptTokens = ENCODING.countTokens(promptTxt.toString());
                }
            }
        } catch (Exception e) {
            System.err.println("计算 promptTokens 失败: " + e.getMessage());
        }

        try (Response upstreamResp = Utils.Client.getOkHttpClient().newCall(request).execute()) {
            if (!upstreamResp.isSuccessful()) {
                // 返回可能存在的响应体
                String errorBody = upstreamResp.body().string();
                throw new IOException("上游返回错误: " + upstreamResp.code() + ", 响应体: " + errorBody);
            }

            /* ---------- 响应头，用 chunked-encoding ---------- */
            Headers h = exchange.getResponseHeaders();
            h.add("Content-Type", "text/event-stream; charset=utf-8");
            h.add("Cache-Control", "no-cache");
            h.add("Connection", "keep-alive");
            exchange.sendResponseHeaders(200, 0);

            OutputStream os = exchange.getResponseBody();
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));

            String convoId = "chatcmpl-" + UUID.randomUUID().toString().replace("-", "");

            /* 用于累计 completion 内容和token (仅当需要 usage 块时) */
            StringBuilder completionBuf = needUsageChunk ? new StringBuilder() : null;
            // 累计的completion tokens计数
            final int[] accumulatedCompletionTokens = {0};

            boolean doneSent = false;
            try {
                // Send initial SSE with empty content and role
                String initialChunk = buildInitialSSEChunk(convoId,"fp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
                writer.write(initialChunk);
                writer.flush();
                
                /* ---- 逐块读取：每有任意新字节就立刻发给前端 ---- */
                final int CHUNK_SIZE = 2048;          // 可自行调整
                okio.Buffer buf = new okio.Buffer();
                while (true) {
                    long n = upstreamResp.body().source().read(buf, CHUNK_SIZE);   // 阻塞，直到 ≥1 字节或 EOF
                    if (n == -1) break;                      // EOF，跳出循环

                    /* 把当前读到的 n 字节全部取出并转 UTF-8 字符串（保持换行符） */
                    String delta = buf.readUtf8(n);
                    System.out.print(delta);
                    
                    // 累计 completion 内容
                    if (needUsageChunk && completionBuf != null) {
                        completionBuf.append(delta);
                        // 计算当前块的token数量
                        int tokenCount = ENCODING.countTokens(delta);
                        // 累计token数量（线程安全地更新）
                        synchronized (accumulatedCompletionTokens) {
                            accumulatedCompletionTokens[0] += tokenCount;
                        }
                    }
                    
                    // 构建内容块SSE（不包含usage）
                    String sseChunk = buildContentSSEChunk(delta, convoId);
                    writer.write(sseChunk);
                    writer.flush();                      // 立即推送
                }

            } catch (Exception e) {
                System.err.println("stream error: " + e.getMessage());
                // 即使出错，也要向前端宣告结束
            } finally {
                // 1. 发送 finish_reason: "stop" 的SSE
                String finishChunk = buildFinishSSEChunk(convoId);
                writer.write(finishChunk);
                writer.flush();
                
                // 2. 如果需要usage，发送usage SSE
                if (needUsageChunk && completionBuf != null) {
                    // 使用累计的token数，而不是重新计算整个内容
                    int completionTokens = accumulatedCompletionTokens[0];
                    int totalTokens = promptTokens + completionTokens;
                    
                    String usageChunk = buildUsageSSEChunk(convoId, promptTokens, completionTokens, totalTokens);
                    writer.write(usageChunk);
                    writer.flush();
                }

                // 3. 发送 [DONE]
                writer.write("data: [DONE]\n\n");
                writer.flush();
                doneSent = true;
                writer.close();      // 也会隐式 close exchange 的 OutputStream
                exchange.close();    // 彻底关闭 TCP
            }
        }
    }

    /**
     * 构建初始SSE块（包含空content和role）
     */
    private String buildInitialSSEChunk(String convoId, String system_fingerprint) {
        JSONObject delta = new JSONObject()
                .put("content", "")
                .put("refusal", JSONObject.NULL)
                .put("role", "assistant");
        
        JSONObject choiceObj = new JSONObject()
                .put("index", 0)
                .put("delta", delta)
                .put("finish_reason", JSONObject.NULL)
                .put("logprobs", JSONObject.NULL);

        JSONObject response = new JSONObject()
                .put("id", convoId)
                .put("object", "chat.completion.chunk")
                .put("created", Instant.now().getEpochSecond())
                .put("model", "gpt-4o-2024-08-06")
                .put("system_fingerprint", system_fingerprint)
                .put("choices", new JSONArray().put(choiceObj))
                .put("usage", JSONObject.NULL);
        
        return "data: " + response.toString() + "\n\n";
    }
    
    /**
     * 构建内容SSE块（不包含usage信息）
     */
    private String buildContentSSEChunk(String deltaContent, String convoId) {
        JSONObject delta = new JSONObject();
        if (deltaContent != null && !deltaContent.isEmpty()) {
            delta.put("content", deltaContent);
        }
        // Don't include role in delta for content chunks
        
        JSONObject choiceObj = new JSONObject()
                .put("index", 0)
                .put("delta", delta)
                .put("finish_reason", JSONObject.NULL)
                .put("logprobs", JSONObject.NULL);

        
        JSONObject response = new JSONObject()
                .put("id", convoId)
                .put("object", "chat.completion.chunk")
                .put("created", Instant.now().getEpochSecond())
                .put("model", "gpt-4o-2024-08-06")
                .put("system_fingerprint", "fp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12))
                .put("choices", new JSONArray().put(choiceObj))
                .put("usage", JSONObject.NULL);
        
        return "data: " + response.toString() + "\n\n";
    }
    
    /**
     * 构建结束SSE块（finish_reason: "stop"）
     */
    private String buildFinishSSEChunk(String convoId) {
        JSONObject choiceObj = new JSONObject()
                .put("index", 0)
                .put("delta", new JSONObject())
                .put("finish_reason", "stop")
                .put("logprobs", JSONObject.NULL);

        JSONObject response = new JSONObject()
                .put("id", convoId)
                .put("object", "chat.completion.chunk")
                .put("created", Instant.now().getEpochSecond())
                .put("model", "gpt-4o-2024-08-06")
                .put("system_fingerprint", "fp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12))
                .put("choices", new JSONArray().put(choiceObj))
                .put("usage", JSONObject.NULL);
        
        return "data: " + response.toString() + "\n\n";
    }
    
    /**
     * 构建usage SSE块
     */
    private String buildUsageSSEChunk(String convoId, int promptTokens, int completionTokens, int totalTokens) {
        JSONObject usage = new JSONObject()
                .put("prompt_tokens", promptTokens)
                .put("completion_tokens", completionTokens)
                .put("total_tokens", totalTokens)
                .put("prompt_tokens_details", new JSONObject()
                        .put("audio_tokens", 0)
                        .put("cached_tokens", 0))
                .put("completion_tokens_details", new JSONObject()
                        .put("accepted_prediction_tokens", 0)
                        .put("audio_tokens", 0)
                        .put("reasoning_tokens", 0)
                        .put("rejected_prediction_tokens", 0));
        
        JSONObject response = new JSONObject()
                .put("id", convoId)
                .put("object", "chat.completion.chunk")
                .put("created", Instant.now().getEpochSecond())
                .put("model", "gpt-4o-2024-08-06")
                .put("system_fingerprint", "fp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12))
                .put("choices", new JSONArray())
                .put("usage", usage);
        
        return "data: " + response.toString() + "\n\n";
    }

    /* =======================================================================
     *  handleNormalResponse
     *  一次性读取上游文本，转换为 OpenAI JSON 后返回
     * ======================================================================= */
    private void handleNormalResponse(HttpExchange exchange, Request request) throws IOException {
        try(Response upstreamResp = Client.getOkHttpClient().newCall(request).execute()) {
            byte[] bytes = upstreamResp.body().bytes();
            Headers h = exchange.getResponseHeaders();
            h.add("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);

        }
    }

}

