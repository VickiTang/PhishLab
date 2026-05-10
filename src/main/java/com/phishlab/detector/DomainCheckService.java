package com.phishlab.detector;

import com.phishlab.util.LevenshteinCalculator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Collections;

public class DomainCheckService {
    private final List<String> trustedDomains;
    private final BrandKeywordMatcher brandMatcher;
    private final DomainEconomicRiskService economicRiskService;
    private final HomoglyphLetterSwapChecker homoglyphChecker;
    private final SuspiciousTldChecker suspiciousTldChecker;
    private final UrlBlocklistService urlBlocklistService;

    public DomainCheckService(List<String> trusted) {
        this.trustedDomains = trusted;
        this.brandMatcher = new BrandKeywordMatcher();
        this.economicRiskService = new DomainEconomicRiskService();
        this.homoglyphChecker = HomoglyphLetterSwapChecker.withDefaults();
        this.suspiciousTldChecker = new SuspiciousTldChecker();
        this.urlBlocklistService = UrlBlocklistService.fromResources();
    }

    public static DomainCheckService withDefaultTrustedDomains() {
        return new DomainCheckService(Arrays.asList(
            "amazon.co.jp", "amazon.com", "google.com", "microsoft.com",
            "apple.com", "netflix.com", "paypal.com", "github.com",
            "rakuten.co.jp", "yahoo.co.jp", "line.me", "twitter.com", "facebook.com",
            "smbc.co.jp", "mufg.jp", "jcb.co.jp", "kuronekoyamato.co.jp"
        ));
    }

    public DetectionResult check(String domain) {
        if (domain == null) return new DetectionResult("null", RiskLevel.GREEN, 0, List.of("ドメインが空です"));
        String target = domain.trim().toLowerCase();

        // 1. 白名单是最高优先级
        if (trustedDomains.contains(target)) {
            return new DetectionResult(target, RiskLevel.GREEN, 0, 
                Collections.singletonList("信頼済みドメインです"));
        }

        // 2. 收集所有 6 个检测器的结果
        List<DetectionResult> results = new ArrayList<>();
        results.add(economicRiskService.check(target));
        results.add(checkByLevenshtein(target));
        results.add(homoglyphChecker.check(target));
        results.add(brandMatcher.check(target));
        results.add(suspiciousTldChecker.check(target));
        results.add(urlBlocklistService.checkDomain(target));

        // 3. 综合判定逻辑 (取最高分数和最高风险)
        RiskLevel finalRisk = RiskLevel.GREEN;
        int maxScore = 0;
        List<String> allReasons = new ArrayList<>();

        for (DetectionResult res : results) {
            if (res.score() > maxScore) {
                maxScore = res.score();
            }
            if (res.riskLevel() != RiskLevel.GREEN) {
                allReasons.addAll(res.reasons());
            }
        }

        // 风险分级映射
        if (maxScore >= 75) {
            finalRisk = RiskLevel.RED;
        } else if (maxScore >= 40) {
            finalRisk = RiskLevel.YELLOW;
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
            reasons.add(closestDomain + " と类似（编辑距离=3）");
        } else {
            level = RiskLevel.GREEN;
            score = 0;
            reasons.add("Levenshtein検出なし");
        }
        return new DetectionResult(domain, level, score, reasons);
    }

    public static void demo() {
        System.out.println("===== Domain Check Service (Bruce Schneier Edition - Full Arsenal) デモ =====");
        DomainCheckService service = withDefaultTrustedDomains();
        System.out.println("信頼済みブランド数: " + service.trustedDomains.size());
        System.out.println();

        String[] testDomains = {
            "amazon.co.jp",                  // 信頼済み (GREEN)
            "amazom.co.jp",                  // ホモグリフ/編集距離 (RED)
            "amazon-verify-login.tk",        // 経済学的リスク: ブランド寄生 + 廉価TLD (RED)
            "m1crosoft.com",                 // Homoglyph catch (RED)
            "smbc.co.jp",                    // 合法 (GREEN)
            "amaz0n-jp.tk",                  // 多重攻撃测试 (RED)
            "example.org"                    // 正常 (GREEN)
        };

        for (int i = 0; i < testDomains.length; i++) {
            System.out.println("テスト" + (i + 1) + ": " + testDomains[i]);
            DetectionResult result = service.check(testDomains[i]);
            System.out.println(result.toString());
            System.out.println("--------------------------------------------------");
        }
    }

    public static void main(String[] args) {
        demo();
    }
}
