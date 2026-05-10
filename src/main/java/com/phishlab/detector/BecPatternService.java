package com.phishlab.detector;

import com.phishlab.generator.BecEmail;
import com.phishlab.generator.BecEmailGenerator;
import com.phishlab.generator.BecTemplates;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * BEC（Business Email Compromise）攻撃パターン検出器。
 */
public class BecPatternService {

    private final List<String> urgencyKeywords;
    private final List<String> moneyKeywords;
    private final List<String> secrecyKeywords;
    private final List<String> impersonationRoles;
    private final Set<String> freeEmailDomains;

    public BecPatternService(List<String> urgencyKeywords, List<String> moneyKeywords, 
                             List<String> secrecyKeywords, List<String> impersonationRoles, 
                             Set<String> freeEmailDomains) {
        this.urgencyKeywords = new ArrayList<>(urgencyKeywords);
        this.moneyKeywords = new ArrayList<>(moneyKeywords);
        this.secrecyKeywords = new ArrayList<>(secrecyKeywords);
        this.impersonationRoles = new ArrayList<>(impersonationRoles);
        this.freeEmailDomains = freeEmailDomains;
    }

    /**
     * 既定の構成で BecPatternService を作成します。
     */
    public static BecPatternService withDefaults() {
        List<String> secrecy = new ArrayList<>(BecTemplates.SECRECY_SHORT_WORDS);
        secrecy.addAll(BecTemplates.SECRECY_FULL_SENTENCES);

        return new BecPatternService(
            BecTemplates.URGENCY_PHRASES,
            BecTemplates.MONEY_PHRASES,
            secrecy,
            BecTemplates.IMPERSONATED_ROLES,
            Set.of("gmail.com", "yahoo.co.jp", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com")
        );
    }

    /**
     * 指定されたメールに対して BEC パターン検知を行います。
     */
    public DetectionResult check(BecEmail email) {
        List<String> reasons = new ArrayList<>();
        int totalScore = 0;

        // 1. URGENCY (+25)
        for (String keyword : urgencyKeywords) {
            if (email.subject().contains(keyword) || email.body().contains(keyword)) {
                totalScore += 25;
                reasons.add("緊急性表現を検出（" + keyword + "）");
                break;
            }
        }

        // 2. MONEY (+25)
        for (String keyword : moneyKeywords) {
            if (email.body().contains(keyword)) {
                totalScore += 25;
                reasons.add("金銭関連表現を検出（" + keyword + "）");
                break;
            }
        }

        // 3. SECRECY (+20)
        for (String keyword : secrecyKeywords) {
            if (email.body().contains(keyword)) {
                totalScore += 20;
                reasons.add("機密性要求を検出（" + keyword + "）");
                break;
            }
        }

        // 4. ROLE_IMPERSONATION (+30) vs 5. SUSPICIOUS_DOMAIN (+20)
        boolean impersonationDetected = false;
        String detectedRole = null;
        for (String role : impersonationRoles) {
            if (email.fromName().contains(role)) {
                detectedRole = role;
                break;
            }
        }

        boolean isFreeEmail = freeEmailDomains.contains(email.fromDomain());

        if (detectedRole != null && isFreeEmail) {
            totalScore += 30;
            reasons.add("権威者なりすまし疑い（" + detectedRole + "を名乗るが、送信元が" + email.fromDomain() + "）");
            impersonationDetected = true;
        } else if (isFreeEmail) {
            totalScore += 20;
            reasons.add("送信ドメインが無料メールサービス（" + email.fromDomain() + "）");
        }

        // スコアの上限
        if (totalScore > 100) totalScore = 100;

        // リスク判定
        RiskLevel riskLevel;
        if (totalScore >= 70) {
            riskLevel = RiskLevel.RED;
        } else if (totalScore >= 40) {
            riskLevel = RiskLevel.YELLOW;
        } else {
            riskLevel = RiskLevel.GREEN;
        }

        if (reasons.isEmpty()) {
            reasons.add("BEC 攻撃パターンは検出されません");
        }

        String target = email.fromName() + " <" + email.fullEmail() + ">";
        return new DetectionResult(target, riskLevel, totalScore, reasons);
    }

    public static void main(String[] args) {
        System.out.println("===== BEC Pattern Service デモ =====");
        System.out.println();
        System.out.println("3 通のメールに対して BEC パターンを検出します。");
        System.out.println();

        BecPatternService service = BecPatternService.withDefaults();

        // テストメール 1: 強い BEC 攻撃
        BecEmailGenerator gen1 = new BecEmailGenerator(42);
        BecEmail email1 = gen1.generate();
        printTestResult(1, "強い BEC 攻撃", email1, service);

        // テストメール 2: 別の BEC
        BecEmailGenerator gen2 = new BecEmailGenerator(43);
        BecEmail email2 = gen2.generate();
        printTestResult(2, "別の BEC", email2, service);

        // テストメール 3: 正常メール（手動構築）
        BecEmail email3 = new BecEmail(
            "明日の会議資料について",
            "山田課長",
            "yourcompany.co.jp",
            "yamada@yourcompany.co.jp",
            "明日の定例会議の資料を共有します。ご確認ください。",
            "課長",
            Collections.emptyList()
        );
        printTestResult(3, "正常メール（手動構築）", email3, service);
    }

    private static void printTestResult(int index, String title, BecEmail email, BecPatternService service) {
        System.out.println("─────────── テストメール " + index + ": " + title + " ───────────");
        System.out.printf("📨 送信者: %s <%s>%n", email.fromName(), email.fullEmail());
        System.out.printf("📨 件名: %s%n", email.subject());
        System.out.println();

        DetectionResult result = service.check(email);
        System.out.println("検出結果: " + result.riskLevel().getIcon() + " " + 
                           result.riskLevel().name() + " " + result.riskLevel().getLabel() + 
                           " (Score: " + result.score() + "/100)");
        System.out.println("判定理由:");
        for (String reason : result.reasons()) {
            System.out.println("  - " + reason);
        }
        System.out.println();
    }
}
