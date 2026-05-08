package com.phishlab.battle;

import com.phishlab.detector.DetectionResult;
import com.phishlab.detector.DomainCheckService;
import com.phishlab.detector.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class ChallengeTest {

    static class Challenge {
        String domain;
        String attackType;
        String category;
        boolean expectThreat;

        Challenge(String domain, String attackType, String category, boolean expectThreat) {
            this.domain = domain;
            this.attackType = attackType;
            this.category = category;
            this.expectThreat = expectThreat;
        }
    }

    public static void main(String[] args) {
        DomainCheckService detector = DomainCheckService.withDefaultTrustedDomains();
        List<Challenge> challenges = new ArrayList<>();

        // 类别 A: Combo Squatting
        challenges.add(new Challenge("amazon-security.com", "amazonにsecurityを連結（典型的なcombo squatting）", "類別 A: Combo Squatting", true));
        challenges.add(new Challenge("amazon-account-verify.net", "amazonに複数キーワードを連結", "類別 A: Combo Squatting", true));
        challenges.add(new Challenge("secure-amazon.co.jp", "合法ブランドの前にsecureを付加", "類別 A: Combo Squatting", true));
        challenges.add(new Challenge("amazon.co.jp.attacker.xyz", "subdomain spoofing（一見amazonに見える）", "類別 A: Combo Squatting", true));

        // 类别 B: TLD 滥用
        challenges.add(new Challenge("amazon.tk", "無料TLDによる仿冒", "類別 B: TLD 滥用", true));
        challenges.add(new Challenge("amazon.top", "怪しいTLDによる仿冒", "類別 B: TLD 滥用", true));

        // 类别 C: 长距离但视觉相似
        challenges.add(new Challenge("arnaz0n.co.jp", "複数文字置換でも視覚的に類似", "類別 C: 長距離類似", true));
        challenges.add(new Challenge("amaz0n-jp.com", "数字置換+ハイフン挿入", "類別 C: 長距離類似", true));

        // 类别 D: 完全无关但应放行
        challenges.add(new Challenge("github.com", "正常なドメイン", "類別 D: 正常ドメイン", false));
        challenges.add(new Challenge("stackoverflow.com", "正常なドメイン（ホワイトリスト外でもOK）", "類別 D: 正常ドメイン", false));

        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║         Challenge Test: 真の攻撃手口に対する防御評価        ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");

        String currentCategory = "";
        int total = 0;
        int leaks = 0;
        int normal = 0;
        int falsePositives = 0;

        for (Challenge c : challenges) {
            if (!c.category.equals(currentCategory)) {
                currentCategory = c.category;
                System.out.println("\n【" + currentCategory + "】");
            }

            DetectionResult result = detector.check(c.domain);
            total++;

            System.out.println("\n📌 " + c.domain);
            System.out.println("   攻撃手口: " + c.attackType);
            System.out.print("   検出結果: " + result.riskLevel().getAnsiColor() + result.riskLevel().getIcon() + " " 
                + result.riskLevel().name() + " " + result.riskLevel().getLabel() 
                + " (Score: " + result.score() + ")" + RiskLevel.reset() + "\n");
            System.out.println("   判定理由: " + String.join(", ", result.reasons()));

            if (c.expectThreat) {
                if (result.riskLevel() == RiskLevel.GREEN) {
                    System.out.println("   \u001B[31m⚠️  漏れ! この攻撃は検出されるべきです\u001B[0m");
                    leaks++;
                }
            } else {
                if (result.riskLevel() == RiskLevel.GREEN) {
                    normal++;
                } else {
                    System.out.println("   \u001B[31m⚠️  誤検出!\u001B[0m");
                    falsePositives++;
                }
            }
        }

        System.out.println("\n════════════════════════════════════════════════════════════");
        System.out.println("📊 サマリー:");
        System.out.println("  刁難サンプル数: " + total + " 件");
        System.out.println("  漏れ件数:       " + leaks + " 件");
        System.out.println("  正常判定:       " + normal + " 件（D類別）");
        System.out.println("  誤検出:         " + falsePositives + " 件");

        System.out.println("\n💡 結論:");
        System.out.println("現在のDomainCheckServiceはtypoSquatに強いが、");
        System.out.println("combo squatting / TLD滥用 / subdomain spoofing には弱い。");
        System.out.println("今後改善が必要な検出戦略:");
        System.out.println("- 品牌キーワード抽出（amazon が部分文字列に含まれるか）");
        System.out.println("- TLD ホワイトリスト/ブラックリスト");
        System.out.println("- サブドメイン構造解析");
    }
}
