package com.phishlab.web;

import com.phishlab.detector.BecPatternService;
import com.phishlab.detector.DetectionResult;
import com.phishlab.detector.DomainCheckService;
import com.phishlab.detector.RiskLevel;
import com.phishlab.detector.UrlBlocklistService;
import com.phishlab.generator.BecEmail;
import com.phishlab.generator.BecEmailGenerator;
import com.phishlab.generator.UrlPhishingEmailGenerator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebServer {

    private static final Pattern URL_PATTERN = Pattern.compile("https?://[\\w\\-./?=&#%~+]+");

    public static void start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));

        server.createContext("/", exchange -> {
            if (!exchange.getRequestURI().getPath().equals("/")) {
                sendResponse(exchange, 404, "text/plain; charset=UTF-8", "Not Found".getBytes(StandardCharsets.UTF_8));
                return;
            }
            try (InputStream in = WebServer.class.getResourceAsStream("/index.html")) {
                if (in == null) {
                    sendResponse(exchange, 404, "text/plain; charset=UTF-8", "index.html not found".getBytes(StandardCharsets.UTF_8));
                    return;
                }
                byte[] bytes = in.readAllBytes();
                sendResponse(exchange, 200, "text/html; charset=UTF-8", bytes);
            }
        });

        server.createContext("/api/health", exchange -> {
            byte[] body = "{\"status\":\"ok\",\"version\":\"0.1\"}".getBytes(StandardCharsets.UTF_8);
            sendResponse(exchange, 200, "application/json; charset=UTF-8", body);
        });

        server.createContext("/api/inbox", exchange -> {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "text/plain; charset=UTF-8", "Method Not Allowed".getBytes(StandardCharsets.UTF_8));
                return;
            }
            byte[] body = buildInboxJson().getBytes(StandardCharsets.UTF_8);
            sendResponse(exchange, 200, "application/json; charset=UTF-8", body);
        });

        server.createContext("/api/check-email", exchange -> {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "application/json; charset=UTF-8", "{\"error\":\"Method Not Allowed\"}".getBytes(StandardCharsets.UTF_8));
                return;
            }
            try {
                String reqBody = readBody(exchange);
                String fromName    = extractJsonField(reqBody, "fromName");
                String fromAddress = extractJsonField(reqBody, "fromAddress");
                String subject     = extractJsonField(reqBody, "subject");
                String body        = extractJsonField(reqBody, "body");

                if (fromName == null || fromAddress == null || subject == null || body == null) {
                    sendResponse(exchange, 400, "application/json; charset=UTF-8", "{\"error\":\"missing field\"}".getBytes(StandardCharsets.UTF_8));
                    return;
                }

                String fromDomain = fromAddress.contains("@") ? fromAddress.substring(fromAddress.indexOf('@') + 1) : fromAddress;
                BecEmail email = new BecEmail(subject, fromName, fromDomain, fromAddress, body, "", List.of());
                DetectionResult becResult = BecPatternService.withDefaults().check(email);

                String becJson = JsonUtil.obj(
                    "riskLevel", JsonUtil.quote(becResult.riskLevel().name()),
                    "riskLabel", JsonUtil.quote(becResult.riskLevel().getLabel()),
                    "score",     String.valueOf(becResult.score()),
                    "reasons",   JsonUtil.quotedArr(becResult.reasons())
                );

                List<String> urlJsonList = new ArrayList<>();
                RiskLevel overallRisk = becResult.riskLevel();
                int overallScore = becResult.score();

                DomainCheckService domainChecker = DomainCheckService.withDefaultTrustedDomains();
                UrlBlocklistService urlBlocklist = UrlBlocklistService.fromResources();
                List<String> urls = extractUrls(body);

                for (String url : urls) {
                    String domain = extractDomain(url);
                    if (domain == null) continue;

                    DetectionResult urlResult;
                    String detectionLayer;

                    // ① 先查 URL 黑名单
                    urlResult = urlBlocklist.checkUrl(url);
                    if (urlResult.riskLevel() != RiskLevel.GREEN) {
                        detectionLayer = "blocklist_url";
                    } else {
                        // ② 查域名黑名单
                        urlResult = urlBlocklist.checkDomain(domain);
                        if (urlResult.riskLevel() != RiskLevel.GREEN) {
                            detectionLayer = "blocklist_domain";
                        } else {
                            // ③ 兜底: 算法检测
                            urlResult = domainChecker.check(domain);
                            detectionLayer = "algorithm";
                        }
                    }

                    urlJsonList.add(JsonUtil.obj(
                        "url",            JsonUtil.quote(url),
                        "domain",         JsonUtil.quote(domain),
                        "riskLevel",      JsonUtil.quote(urlResult.riskLevel().name()),
                        "riskLabel",      JsonUtil.quote(urlResult.riskLevel().getLabel()),
                        "score",          String.valueOf(urlResult.score()),
                        "reasons",        JsonUtil.quotedArr(urlResult.reasons()),
                        "detectionLayer", JsonUtil.quote(detectionLayer)
                    ));

                    if (urlResult.riskLevel().ordinal() > overallRisk.ordinal()) {
                        overallRisk = urlResult.riskLevel();
                    }
                    if (urlResult.score() > overallScore) {
                        overallScore = urlResult.score();
                    }
                }

                String respJson = JsonUtil.obj(
                    "bec",         becJson,
                    "urls",        JsonUtil.arr(urlJsonList),
                    "overallRisk", JsonUtil.quote(overallRisk.name()),
                    "overallScore", String.valueOf(overallScore)
                );
                sendResponse(exchange, 200, "application/json; charset=UTF-8", respJson.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                String errJson = "{\"error\":" + JsonUtil.quote(e.getMessage() != null ? e.getMessage() : "unknown error") + "}";
                sendResponse(exchange, 500, "application/json; charset=UTF-8", errJson.getBytes(StandardCharsets.UTF_8));
            }
        });

        server.createContext("/api/check-domain", exchange -> {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "application/json; charset=UTF-8", "{\"error\":\"Method Not Allowed\"}".getBytes(StandardCharsets.UTF_8));
                return;
            }
            try {
                String reqBody = readBody(exchange);
                String domain = extractJsonField(reqBody, "domain");

                if (domain == null) {
                    sendResponse(exchange, 400, "application/json; charset=UTF-8", "{\"error\":\"missing field\"}".getBytes(StandardCharsets.UTF_8));
                    return;
                }

                DetectionResult result = DomainCheckService.withDefaultTrustedDomains().check(domain);

                String respJson = JsonUtil.obj(
                    "riskLevel", JsonUtil.quote(result.riskLevel().name()),
                    "riskLabel", JsonUtil.quote(result.riskLevel().getLabel()),
                    "score",     String.valueOf(result.score()),
                    "reasons",   JsonUtil.quotedArr(result.reasons())
                );
                sendResponse(exchange, 200, "application/json; charset=UTF-8", respJson.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                String errJson = "{\"error\":" + JsonUtil.quote(e.getMessage() != null ? e.getMessage() : "unknown error") + "}";
                sendResponse(exchange, 500, "application/json; charset=UTF-8", errJson.getBytes(StandardCharsets.UTF_8));
            }
        });

        server.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() ->
            System.out.println("\nWebServer を停止しました")
        ));

        System.out.println("\033[36m╔════════════════════════════════════════╗\033[0m");
        System.out.println("\033[36m║\033[0m   PhishLab Web Server 起動              \033[36m║\033[0m");
        System.out.println("\033[36m╠════════════════════════════════════════╣\033[0m");
        System.out.println("\033[36m║\033[0m   ブラウザでアクセス:                   \033[36m║\033[0m");
        System.out.println("\033[36m║\033[0m   \033[4mhttp://localhost:" + port + "\033[0m                 \033[36m║\033[0m");
        System.out.println("\033[36m║\033[0m                                         \033[36m║\033[0m");
        System.out.println("\033[36m║\033[0m   終了: Ctrl+C                          \033[36m║\033[0m");
        System.out.println("\033[36m╚════════════════════════════════════════╝\033[0m");
    }

    private static String buildInboxJson() {
        List<String> emails = new ArrayList<>();

        long baseSeed = System.currentTimeMillis();
        BecEmailGenerator generator = new BecEmailGenerator(baseSeed);
        List<BecEmail> phishEmails = generator.generateBatch(3);

        for (int i = 0; i < phishEmails.size(); i++) {
            BecEmail bec = phishEmails.get(i);
            String id = "phish-" + baseSeed + "-" + i;
            emails.add(JsonUtil.obj(
                "id",          JsonUtil.quote(id),
                "isPhishing",  "true",
                "type",        JsonUtil.quote("bec"),
                "fromName",    JsonUtil.quote(bec.fromName()),
                "fromAddress", JsonUtil.quote(bec.fullEmail()),
                "subject",     JsonUtil.quote(bec.subject()),
                "body",        JsonUtil.quote(bec.body())
            ));
        }

        UrlPhishingEmailGenerator urlGenerator = new UrlPhishingEmailGenerator(baseSeed);
        List<BecEmail> urlEmails = urlGenerator.generateBatch(3);
        for (int i = 0; i < urlEmails.size(); i++) {
            BecEmail url = urlEmails.get(i);
            String id = "url-" + baseSeed + "-" + i;
            emails.add(JsonUtil.obj(
                "id",          JsonUtil.quote(id),
                "isPhishing",  "true",
                "type",        JsonUtil.quote("phishing-url"),
                "fromName",    JsonUtil.quote(url.fromName()),
                "fromAddress", JsonUtil.quote(url.fullEmail()),
                "subject",     JsonUtil.quote(url.subject()),
                "body",        JsonUtil.quote(url.body())
            ));
        }

        emails.add(JsonUtil.obj(
            "id",          JsonUtil.quote("email-normal-004"),
            "isPhishing",  "false",
            "type",        JsonUtil.quote("normal"),
            "fromName",    JsonUtil.quote("山田課長"),
            "fromAddress", JsonUtil.quote("yamada@yourcompany.co.jp"),
            "subject",     JsonUtil.quote("明日の会議資料について"),
            "body",        JsonUtil.quote("山田です。\n\n明日の定例会議の資料を共有します。\n添付ファイルをご確認ください。\n\nよろしくお願いします。")
        ));

        emails.add(JsonUtil.obj(
            "id",          JsonUtil.quote("email-normal-005"),
            "isPhishing",  "false",
            "type",        JsonUtil.quote("normal"),
            "fromName",    JsonUtil.quote("佐藤さん"),
            "fromAddress", JsonUtil.quote("sato@partner-corp.co.jp"),
            "subject",     JsonUtil.quote("プロジェクト進捗のご共有"),
            "body",        JsonUtil.quote("佐藤です。\n\n今週の进捗をまとめました。\nお手すきの際にご確認お願いします。\n\nどうぞよろしくお願いします。")
        ));

        return JsonUtil.arr(emails);
    }

    private static List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) {
            urls.add(m.group());
        }
        return urls;
    }

    private static String extractDomain(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return host != null ? host.toLowerCase() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (var reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    private static String extractJsonField(String json, String fieldName) {
        Pattern p = Pattern.compile("\"" + fieldName + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1)
                    .replace("\\n", "\n")
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\");
        }
        return null;
    }

    private static void sendResponse(HttpExchange exchange, int status, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
