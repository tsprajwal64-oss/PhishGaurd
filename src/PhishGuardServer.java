import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PhishGuardServer {
    private static final int PORT = 8081;
    private static final int MAX_BODY = 100_000;

    interface DetectionRule { int check(String email, List<String> findings); }

    abstract static class BaseRule implements DetectionRule {
        protected void finding(List<String> findings, String text) { findings.add(text); }
    }

    static class KeywordRule extends BaseRule {
        public int check(String email, List<String> findings) {
            String text = email.toLowerCase(Locale.ROOT);
            String[] terms = {"urgent", "verify your account", "password", "bank details",
                "click here", "suspended", "claim your prize", "otp", "update payment"};
            int score = 0;
            for (String term : terms) if (text.contains(term)) {
                score += 15;
                finding(findings, "Suspicious keyword or phrase: " + term);
            }
            return score;
        }
    }

    static class LinkRule extends BaseRule {
        public int check(String email, List<String> findings) {
            String text = email.toLowerCase(Locale.ROOT);
            int score = 0;
            if (text.contains("http://")) {
                score += 20;
                finding(findings, "Insecure HTTP link detected");
            }
            if (text.contains("bit.ly") || text.contains("tinyurl.com") || text.contains("t.co/")) {
                score += 25;
                finding(findings, "URL shortener detected");
            }
            if (text.matches("(?s).*https?://[^\\s]*@[^\\s]*.*")) {
                score += 25;
                finding(findings, "URL contains an @ symbol, which can obscure its destination");
            }
            return score;
        }
    }

    static class EmailScanner {
        private final DetectionRule[] rules = {new KeywordRule(), new LinkRule()};
        int scan(String email, List<String> findings) {
            int total = 0;
            for (DetectionRule rule : rules) total += rule.check(email, findings);
            return Math.min(total, 100);
        }
    }

    private static String json(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 32) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    private static String body(HttpExchange ex) throws IOException {
        byte[] data = ex.getRequestBody().readNBytes(MAX_BODY + 1);
        if (data.length > MAX_BODY) throw new IllegalArgumentException("Request exceeds 100 KB.");
        return new String(data, StandardCharsets.UTF_8);
    }

    private static void file(HttpExchange ex, String name, String type) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "text/plain; charset=UTF-8", "Method not allowed");
            return;
        }
        Path path = Path.of("public", name).normalize();
        if (!Files.isRegularFile(path)) {
            send(ex, 404, "text/plain; charset=UTF-8", "File not found");
            return;
        }
        byte[] data = Files.readAllBytes(path);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.getResponseHeaders().set("Cache-Control", "no-cache");
        ex.sendResponseHeaders(200, data.length);
        ex.getResponseBody().write(data);
        ex.close();
    }

    private static void analyze(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=UTF-8", "{\"error\":\"Use POST.\"}");
            return;
        }
        final String email;
        try {
            email = body(ex);
        } catch (IllegalArgumentException e) {
            send(ex, 413, "application/json; charset=UTF-8", "{\"error\":" + json(e.getMessage()) + "}");
            return;
        }
        if (email.isBlank()) {
            send(ex, 400, "application/json; charset=UTF-8", "{\"error\":\"Email content is empty.\"}");
            return;
        }

        List<String> findings = new ArrayList<>();
        int score = new EmailScanner().scan(email, findings);
        String status = score >= 50 ? "Phishing" : score >= 20 ? "Suspicious" : "Safe";
        StringBuilder list = new StringBuilder("[");
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) list.append(",");
            list.append(json(findings.get(i)));
        }
        list.append("]");
        send(ex, 200, "application/json; charset=UTF-8",
            "{\"score\":" + score + ",\"status\":" + json(status) + ",\"findings\":" + list + "}");
    }

    private static void investigate(HttpExchange ex, HttpClient client) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=UTF-8", "{\"error\":\"Use POST.\"}");
            return;
        }
        final String email;
        try {
            email = body(ex).trim();
        } catch (IllegalArgumentException e) {
            send(ex, 413, "application/json; charset=UTF-8", "{\"error\":" + json(e.getMessage()) + "}");
            return;
        }
        int at = email.lastIndexOf('@');
        if (at <= 0 || at == email.length() - 1) {
            send(ex, 400, "application/json; charset=UTF-8", "{\"error\":\"Enter a valid email address.\"}");
            return;
        }
        String domain = email.substring(at + 1).toLowerCase(Locale.ROOT);
        if (!domain.matches("[a-z0-9.-]+\\.[a-z]{2,}")) {
            send(ex, 400, "application/json; charset=UTF-8", "{\"error\":\"Invalid sender domain format.\"}");
            return;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://rdap.org/domain/" + domain))
                .timeout(Duration.ofSeconds(8))
                .header("Accept", "application/rdap+json, application/json")
                .GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String created = "";
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                Matcher matcher = Pattern.compile("\"eventAction\"\\s*:\\s*\"registration\"\\s*,\\s*\"eventDate\"\\s*:\\s*\"([^\"]+)\"").matcher(response.body());
                if (matcher.find()) created = matcher.group(1);
                send(ex, 200, "application/json; charset=UTF-8",
                    "{\"domain\":" + json(domain) + ",\"lookupStatus\":\"RDAP record found\",\"createdDate\":" + json(created) +
                    ",\"note\":\"Public registration data only. This does not authenticate the sender or verify SPF, DKIM or DMARC.\"}");
            } else {
                send(ex, 200, "application/json; charset=UTF-8",
                    "{\"domain\":" + json(domain) + ",\"lookupStatus\":\"No public record returned\",\"createdDate\":\"\"," +
                    "\"note\":\"The registry did not return usable information. This is not proof of safety or maliciousness.\"}");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            send(ex, 502, "application/json; charset=UTF-8", "{\"error\":\"Domain lookup interrupted.\"}");
        } catch (Exception e) {
            send(ex, 502, "application/json; charset=UTF-8", "{\"error\":\"RDAP lookup failed. Check internet access and retry.\"}");
        }
    }

    public static void main(String[] args) throws Exception {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/api/analyze", PhishGuardServer::analyze);
        server.createContext("/api/investigate", ex -> investigate(ex, client));
        server.createContext("/phishing.css", ex -> file(ex, "phishing.css", "text/css; charset=UTF-8"));
        server.createContext("/phishing.js", ex -> file(ex, "phishing.js", "application/javascript; charset=UTF-8"));
        server.createContext("/", ex -> file(ex, "index.html", "text/html; charset=UTF-8"));
        server.start();

        System.out.println("PhishGuard running at http://localhost:" + PORT);
        System.out.println("Press Ctrl+C to stop.");
    }
}
