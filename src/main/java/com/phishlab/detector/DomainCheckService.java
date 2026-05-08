package com.phishlab.detector;

import com.phishlab.util.LevenshteinCalculator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Collections;

public class DomainCheckService {
    private final List<String> trustedDomains;
    private final BrandKeywordMatcher brandMatcher;
    private final SuspiciousTldChecker tldChecker;

    public DomainCheckService(List<String> trusted) {
        this.trustedDomains = trusted;
        this.brandMatcher = new BrandKeywordMatcher();
        this.tldChecker = new SuspiciousTldChecker();
    }

    public static DomainCheckService withDefaultTrustedDomains() {
        return new DomainCheckService(Arrays.asList(
            "amazon.co.jp", "amazon.com", "google.com", "microsoft.com",
            "apple.com", "netflix.com", "paypal.com", "github.com",
            "rakuten.co.jp", "yahoo.co.jp", "line.me", "twitter.com", "facebook.com"
        ));
    }

    public DetectionResult check(String domain) {
        String target = domain.trim().toLowerCase();

        // Whitelist is a special case: immediate return
        if (trustedDomains.contains(target)) {
            return new DetectionResult(target, RiskLevel.GREEN, 0, 
                Collections.singletonList("このドメインは信頼ホワイトリストに含まれます"));
        }

        // 收集所有策略的结果
        List<DetectionResult> results = new ArrayList<>();
        results.add(checkByLevenshtein(target));
        results.add(brandMatcher.check(target));
        results.add(tldChecker.check(target));

        // 1. 取最高风险（RED > YELLOW > GREEN）
        RiskLevel finalRisk = RiskLevel.GREEN;
        for (DetectionResult res : results) {
            if (res.riskLevel() == RiskLevel.RED) {
                finalRisk = RiskLevel.RED;
                break; // RED is highest, can stop
            } else if (res.riskLevel() == RiskLevel.YELLOW) {
                finalRisk = RiskLevel.YELLOW;
            }
        }

        // 2. 合并所有非 GREEN 的判定理由
        List<String> allReasons = new ArrayList<>();
        int maxScore = 0;
        for (DetectionResult res : results) {
            if (res.riskLevel() != RiskLevel.GREEN) {
                allReasons.addAll(res.reasons());
                // 3. 取最高分数
                if (res.score() > maxScore) {
                    maxScore = res.score();
                }
            }
        }

        if (allReasons.isEmpty()) {
            allReasons.add("顕著ななりすましパターンは検出されません");
        }

        return new DetectionResult(target, finalRisk, maxScore, allReasons);
    }

    private DetectionResult checkByLevenshtein(String domain) {
        int minDistance = Integer.MAX_VALUE;
        String closestDomain = "";

        for (String trusted : trustedDomains) {
            int distance = LevenshteinCalculator.distance(domain, trusted);
            if (distance < minDistance) {
                minDistance = distance;
                closestDomain = trusted;
            }
        }

        RiskLevel level;
        int score;
        List<String> reasons = new ArrayList<>();
        if (minDistance == 1) {
            level = RiskLevel.RED;
            score = 90;
            reasons.add(closestDomain + " のなりすましの可能性（編集距離=1）");
        } else if (minDistance == 2) {
            level = RiskLevel.YELLOW;
            score = 60;
            reasons.add(closestDomain + " のなりすましの可能性（編集距離=2）");
        } else if (minDistance == 3) {
            level = RiskLevel.YELLOW;
            score = 40;
            reasons.add(closestDomain + " と類似（編集距离=3）");
        } else {
            level = RiskLevel.GREEN;
            score = 0;
            reasons.add("Levenshtein検出なし");
        }
        return new DetectionResult(domain, level, score, reasons);
    }

    public static void demo() {
        System.out.println("===== Domain Check Service (Multi-Strategy) デモ =====");
        DomainCheckService service = withDefaultTrustedDomains();
        System.out.println("ホワイトリスト読込済: " + service.trustedDomains.size() + " 件の信頼ブランド");
        System.out.println();

        // 保持原来的 5 条测试用例
        String[] testDomains = {
            "amazon.co.jp",
            "arnazon.co.jp",
            "amazom.co.jp",
            "amzaon.co.jp",
            "example.org"
        };

        for (int i = 0; i < testDomains.length; i++) {
            System.out.println("テスト" + (i + 1) + ": " + testDomains[i]);
            System.out.print(service.check(testDomains[i]).toString());
            System.out.println();
        }
    }

    public static void main(String[] args) {
        demo();
    }
}
