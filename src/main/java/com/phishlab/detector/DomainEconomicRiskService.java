package com.phishlab.detector;

import java.util.*;

/**
 * DomainEconomicRiskService
 * 
 * 基于 Bruce Schneier 的「安全经济学」理论构建。
 * 核心逻辑：不依赖静态黑名单，而是通过计算攻击者的「逃逸成本」和「信誉建立税」来识别风险。
 */
public class DomainEconomicRiskService {

    private final BrandKeywordMatcher brandMatcher;
    private final Set<String> lowCostTlds;
    private final Set<String> highRepTlds;

    public DomainEconomicRiskService() {
        this.brandMatcher = new BrandKeywordMatcher();
        
        // 廉价 TLD (攻击者首选，因为「烧掉」它们的经济成本极低)
        this.lowCostTlds = new HashSet<>(Arrays.asList(
            "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "site", "online", 
            "shop", "link", "click", "work", "loan", "zip", "mov", "monster", "icu"
        ));

        // 高信誉/高门槛 TLD (注册成本高，或需要实名/企业资质)
        this.highRepTlds = new HashSet<>(Arrays.asList(
            "com", "jp", "co.jp", "edu", "gov", "ac.jp", "ne.jp", "org", "net"
        ));
    }

    public DetectionResult check(String domain) {
        if (domain == null || domain.isEmpty()) {
            return new DetectionResult("", RiskLevel.GREEN, 0, List.of("ドメインが空です"));
        }

        String target = domain.toLowerCase().trim();
        List<String> reasons = new ArrayList<>();
        int riskScore = 0;

        // 1. TLD 经济学评估 (Economic Cost Analysis)
        String tld = getTld(target);
        if (lowCostTlds.contains(tld)) {
            riskScore += 45;
            reasons.add("低コストTLD (" + tld + "): 攻撃者の使い捨て(ROI)効率が極めて高い");
        } else if (!highRepTlds.contains(tld)) {
            riskScore += 20;
            reasons.add("特殊なTLD (" + tld + "): 防御側の可視性を下げるための選択");
        }

        // 2. 品牌信誉劫持分析 (Reputation Hijacking)
        DetectionResult brandResult = brandMatcher.check(target);
        if (brandResult.riskLevel() == RiskLevel.RED) {
            riskScore += 50;
            reasons.add("ブランド名寄生: 正規ブランドの信誉を無断で借用(Impersonation)");
        }

        // 3. 信息熵分析 (Entropy Analysis / DGA Detection)
        double entropy = calculateEntropy(target);
        if (entropy > 3.8 && target.length() > 10) {
            riskScore += 35;
            reasons.add("高エントロピードメイン (値=" + String.format("%.2f", entropy) + "): 自動生成(DGA)の疑い");
        }

        // 4. 结构性混淆分析 (Structural Obfuscation)
        if (target.contains("--") || (target.split("-").length > 3)) {
            riskScore += 25;
            reasons.add("過度なハイフン使用: URLの視覚的複雑性を高める典型的な手法");
        }
        
        // 5. 子域名深度分析
        long dotCount = target.chars().filter(ch -> ch == '.').count();
        if (dotCount > 3) {
            riskScore += 20;
            reasons.add("異常なサブドメイン深度: ホスト名の階層を利用した偽装");
        }

        // 最终风险判定 (Schneier 式累加博弈模型)
        RiskLevel level;
        if (riskScore >= 75) {
            level = RiskLevel.RED;
        } else if (riskScore >= 40) {
            level = RiskLevel.YELLOW;
        } else {
            level = RiskLevel.GREEN;
        }

        if (reasons.isEmpty()) {
            reasons.add("経済学的特徴に異常なし");
        }

        return new DetectionResult(target, level, Math.min(riskScore, 100), reasons);
    }

    private String getTld(String domain) {
        int lastDot = domain.lastIndexOf('.');
        if (lastDot != -1 && lastDot < domain.length() - 1) {
            return domain.substring(lastDot + 1);
        }
        return "";
    }

    /**
     * 计算香农熵 (Shannon Entropy)
     * 用来量化域名的随机性，识别机器生成的域名。
     */
    private double calculateEntropy(String s) {
        Map<Character, Integer> counts = new HashMap<>();
        for (char c : s.toCharArray()) {
            counts.put(c, counts.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        for (Integer count : counts.values()) {
            double p = (double) count / s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
