package com.phishlab.detector;

import com.phishlab.hash.HashUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UrlBlocklistService {
    private final Set<String> urlHashBlocklist;
    private final Set<String> domainBlocklist;

    public UrlBlocklistService(Set<String> urlHashes, Set<String> domains) {
        this.urlHashBlocklist = Collections.unmodifiableSet(urlHashes);
        this.domainBlocklist = Collections.unmodifiableSet(domains);
    }

    public static UrlBlocklistService fromResources() {
        Set<String> urlHashes = new HashSet<>();
        Set<String> domains = new HashSet<>();

        loadUrlHashes(urlHashes);
        loadDomains(domains);

        return new UrlBlocklistService(urlHashes, domains);
    }

    private static void loadUrlHashes(Set<String> urlHashes) {
        try (InputStream is = UrlBlocklistService.class.getResourceAsStream("/data/url-blocklist.txt")) {
            if (is == null) return;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    urlHashes.add(HashUtils.sha256(line));
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading URL blocklist: " + e.getMessage());
        }
    }

    private static void loadDomains(Set<String> domains) {
        try (InputStream is = UrlBlocklistService.class.getResourceAsStream("/data/domain-blocklist.txt")) {
            if (is == null) return;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    domains.add(line.toLowerCase());
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading domain blocklist: " + e.getMessage());
        }
    }

    public DetectionResult checkUrl(String url) {
        String hash = HashUtils.sha256(url);
        if (urlHashBlocklist.contains(hash)) {
            return new DetectionResult(url, RiskLevel.RED, 100, List.of("既知のフィッシング URL（脅威情報DB ヒット）"));
        }
        return new DetectionResult(url, RiskLevel.GREEN, 0, List.of("脅威情報 DB ヒットなし"));
    }

    public DetectionResult checkDomain(String domain) {
        String lowerDomain = domain.toLowerCase();
        if (domainBlocklist.contains(lowerDomain)) {
            return new DetectionResult(domain, RiskLevel.RED, 95, List.of("既知の悪意あるドメイン（脅威情報DB）"));
        }
        return new DetectionResult(domain, RiskLevel.GREEN, 0, List.of("脅威情報 DB ヒットなし"));
    }

    public static void main(String[] args) {
        UrlBlocklistService service = UrlBlocklistService.fromResources();

        System.out.println("===== UrlBlocklistService デモ =====");
        System.out.println();
        System.out.println("URL ハッシュブロックリスト件数: " + service.urlHashBlocklist.size());
        System.out.println("ドメインブロックリスト件数: " + service.domainBlocklist.size());
        System.out.println();

        System.out.println("テスト1: https://amazon-security-jp.tk/login");
        System.out.println(service.checkUrl("https://amazon-security-jp.tk/login"));

        System.out.println("テスト2: phish-paypal.tk");
        System.out.println(service.checkDomain("phish-paypal.tk"));

        System.out.println("テスト3: https://google.com");
        System.out.println(service.checkUrl("https://google.com"));

        System.out.println("テスト4: example.org");
        System.out.println(service.checkDomain("example.org"));
    }
}
