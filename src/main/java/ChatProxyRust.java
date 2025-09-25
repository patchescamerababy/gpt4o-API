import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.json.JSONArray;
import org.json.JSONObject;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import Utils.Client;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Java rewrite of Rust ChatProxy - maintains same functionality as Rust version
 * Fixed Rust compilation warnings and errors:
 * - Removed unused serde imports
 * - Fixed borrow checker issue with reqwest::Response
 */
public class ChatProxyRust implements HttpHandler {

    // Constants matching Rust version
    private static final String UPSTREAM_BASE = "https://python-app-qjk4mlqqha-uc.a.run.app";
    private static final String MODEL_NAME = "gpt-4o-2024-08-06";

    // Token cache matching Rust TokenCache struct
    private static class TokenCache {
        private String token;
        private long exp;

        public TokenCache() {
            this.token = null;
            this.exp = 0;
        }

        public boolean isValid() {
            if (exp >= 30) {
                return (exp - 30) > getCurrentUnixTime();
            }
            return false;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
        public long getExp() { return exp; }
        public void setExp(long exp) { this.exp = exp; }
    }

    private final TokenCache tokenCache = new TokenCache();
    private final ExecutorService executor = Executors.newFixedThreadPool(
            Runtime.getRuntime().availableProcessors()
    );

    public ChatProxyRust() {
        // Initialize token on construction like Rust version
        try {
            refreshToken();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize token", e);
        }
    }

    private static long getCurrentUnixTime() {
        return Instant.now().getEpochSecond();
    }

    /**
     * Refresh token logic matching Rust version
     */
    private synchronized void refreshToken() throws Exception {
        OkHttpClient client = Client.getOkHttpClient();
        Request request = new Request.Builder()
                .url(UPSTREAM_BASE + "/token")
                .post(RequestBody.create("", MediaType.get("application/json")))
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new Exception("Failed to get new token");
            }

            String responseBody = response.body().string();
            JSONObject bearer = new JSONObject(responseBody);
            String accessToken = bearer.optString("access_token");

            if (accessToken == null || accessToken.isEmpty()) {
                throw new Exception("access_token missing");
            }

            // Decode JWT payload to get exp (same as Rust)
            String[] parts = accessToken.split("\\.");
            if (parts.length < 2) {
                throw new Exception("Invalid JWT structure");
            }

            byte[] decodedPayload = Base64.getUrlDecoder().decode(parts[1]);
            String payloadStr = new String(decodedPayload, StandardCharsets.UTF_8);
            JSONObject payload = new JSONObject(payloadStr);
            long exp = payload.optLong("exp", 0);

            if (exp == 0) {
                throw new Exception("Expiration time missing");
            }

            tokenCache.setToken(accessToken);
            tokenCache.setExp(exp);
        }
    }

    /**
     * Ensure valid token matching Rust version
     */
    private synchronized void ensureValidToken() throws Exception {
        long now = getCurrentUnixTime();
        if (tokenCache.getToken() == null || now >= tokenCache.getExp()) {
            refreshToken();
        }
    }

    /**
     * Normalize a message: flatten text array, handle image_url to data URI
     * Direct port from Rust normalize_message function
     */
    private JSONObject normalizeMessage(JSONObject message) {
        JSONObject result = new JSONObject(message.toString()); // Clone

        if (result.has("content") && result.get("content") instanceof JSONArray) {
            JSONArray contentArray = result.getJSONArray("content");

            // Check if all are type="text"
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
                    combined.append('\n');
                }
                combined.append(text);
            }

            if (allText) {
                // Flatten to simple content string
                JSONObject flat = new JSONObject();
                flat.put("role", result.optString("role", "user"));
                flat.put("content", combined.toString());
                return flat;
            }

            // Not all text, handle image_url
            for (int i = 0; i < contentArray.length(); i++) {
                JSONObject item = contentArray.optJSONObject(i);
                if (item != null && "image_url".equals(item.optString("type"))) {
                    JSONObject imageUrlObj = item.optJSONObject("image_url");
                    if (imageUrlObj != null && imageUrlObj.has("url")) {
                        String url = imageUrlObj.optString("url");
                        if (!url.startsWith("data:image/")) {
                            try {
                                // Download image and convert to data URI (same logic as Rust)
                                Request imageRequest = new Request.Builder().url(url).build();
                                try (Response imageResponse = Client.getOkHttpClient().newCall(imageRequest).execute()) {
                                    if (imageResponse.isSuccessful() && imageResponse.body() != null) {
                                        // Get content-type before reading bytes (fixes Rust borrow issue)
                                        String contentType = imageResponse.header("Content-Type");
                                        if (contentType == null || !contentType.startsWith("image/")) {
                                            contentType = "image/png";
                                        }

                                        byte[] imageBytes = imageResponse.body().bytes();
                                        String base64Image = Base64.getEncoder().encodeToString(imageBytes);
                                        String dataUri = "data:" + contentType + ";base64," + base64Image;
                                        imageUrlObj.put("url", dataUri);
                                    }
                                }
                            } catch (Exception e) {
                                System.err.printf("Error processing image URL=%s: %s%n", url, e.getMessage());
                            }
                        }
                    }
                }
            }
        }

        return result;
    }

    /**
     * Normalize all messages in array
     * Direct port from Rust normalize_messages function
     */
    private JSONArray normalizeMessages(JSONArray messages) {
        JSONArray newMessages = new JSONArray();

        for (int i = 0; i < messages.length(); i++) {
            JSONObject message = messages.getJSONObject(i);
            JSONObject normalized = normalizeMessage(message);
            newMessages.put(normalized);

            // If original message contains image_url, insert empty user message
            boolean hasImageUrl = false;
            if (message.has("content") && message.get("content") instanceof JSONArray) {
                JSONArray contentArray = message.getJSONArray("content");
                for (int j = 0; j < contentArray.length(); j++) {
                    JSONObject contentItem = contentArray.optJSONObject(j);
                    if (contentItem != null &&
                        "image_url".equals(contentItem.optString("type")) &&
                        contentItem.has("image_url")) {
                        hasImageUrl = true;
                        break;
                    }
                }
            }

            if (hasImageUrl) {
                JSONObject emptyUserMsg = new JSONObject();
                emptyUserMsg.put("role", "user");
                emptyUserMsg.put("content", "");
                newMessages.put(emptyUserMsg);
            }
        }

        return newMessages;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            ensureValidToken();
        } catch (Exception e) {
            sendError(exchange, "Token error: " + e.getMessage(), 500);
            return;
        }

        // CORS headers
        Headers headers = exchange.getResponseHeaders();
        headers.add("Access-Control-Allow-Origin", "*");
        headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization");

        String method = exchange.getRequestMethod().toUpperCase();

        if ("OPTIONS".equals(method)) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if ("GET".equals(method)) {
            String response = "<html><head><title>欢迎使用API</title></head><body><h1>欢迎使用API</h1><p>此 API 用于与 ChatGPT / Claude 模型交互。您可以发送消息给模型并接收响应。</p></body></html>";
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, response.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes(StandardCharsets.UTF_8));
            }
            return;
        }

        if (!"POST".equals(method)) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        // Handle POST request asynchronously
        CompletableFuture.runAsync(() -> {
            try (InputStream is = exchange.getRequestBody()) {
                // Parse request body
                String reqBody = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))
                        .lines().reduce("", (acc, line) -> acc + line);
                JSONObject reqJson = new JSONObject(reqBody);

                // Extract parameters
                JSONArray messages = reqJson.optJSONArray("messages");
                if (messages == null) messages = new JSONArray();

                String modelName = reqJson.optString("model", MODEL_NAME);
                boolean isStream = reqJson.optBoolean("stream", false);

                // Normalize messages using Rust-equivalent logic
                JSONArray normalizedMessages = normalizeMessages(messages);

                // Build upstream request - clone the original request to preserve all fields
                JSONObject requestJson = new JSONObject(reqJson.toString());
                
                // Only replace the messages field, preserving all other fields
                requestJson.put("messages", normalizedMessages);
                
                // Ensure model and stream are set (in case they weren't in the original)
                if (!requestJson.has("model")) {
                    requestJson.put("model", modelName);
                }
                if (!requestJson.has("stream")) {
                    requestJson.put("stream", isStream);
                }

                // Make upstream request
                Request upstreamReq = new Request.Builder()
                        .url(UPSTREAM_BASE + "/ai/chat/completion")
                        .header("Authorization", "Bearer " + tokenCache.getToken())
                        .header("Content-Type", "application/json")
                        .post(RequestBody.create(requestJson.toString(), MediaType.get("application/json")))
                        .build();

                handleUpstreamResponse(exchange, upstreamReq);

            } catch (Exception e) {
                e.printStackTrace();
                sendError(exchange, "Internal server error: " + e.getMessage(), 500);
            }
        }, executor);
    }

    private void handleUpstreamResponse(HttpExchange exchange, Request request) {
        try (Response response = Client.getOkHttpClient().newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                String responseBody = response.body().string();
                
                Headers headers = exchange.getResponseHeaders();
                headers.add("Content-Type", "application/json; charset=utf-8");
                
                byte[] responseBytes = responseBody.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, responseBytes.length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
            } else {
                String errorBody = response.body() != null ? response.body().string() : "Error";
                sendError(exchange, errorBody, response.code());
            }
        } catch (Exception e) {
            sendError(exchange, "Error: " + e.getMessage(), 500);
        }
    }

    private void sendError(HttpExchange exchange, String message, int code) {
        try {
            Headers headers = exchange.getResponseHeaders();
            headers.add("Content-Type", "text/plain; charset=utf-8");
            byte[] responseBytes = message.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(code, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
