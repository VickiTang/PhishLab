package com.phishlab.battle;

import com.phishlab.detector.DetectionResult;
import com.phishlab.detector.DomainCheckService;
import com.phishlab.detector.RiskLevel;
import com.phishlab.generator.PhishingDomainGenerator;

import java.util.*;

public class BattleRunner {
    private final PhishingDomainGenerator generator;
    private final DomainCheckService detector;

    public BattleRunner(PhishingDomainGenerator generator, DomainCheckService detector) {
        this.generator = generator;
        this.detector = detector;
    }

    public static BattleRunner withDefaults() {
        return new BattleRunner(
            new PhishingDomainGenerator(),
            DomainCheckService.withDefaultTrustedDomains()
        );
    }

    public BattleResult run(String target, int rounds) {
        Set<String> allVariants = new HashSet<>();
        for (int i = 0; i < rounds; i++) {
            allVariants.addAll(generator.typoSquat(target));
        }

        List<String> detectedVariants = new ArrayList<>();
        List<String> missedVariants = new ArrayList<>();
        int detectedCount = 0;
        int missedCount = 0;

        for (String variant : allVariants) {
            DetectionResult result = detector.check(variant);
            if (result.riskLevel() != RiskLevel.GREEN) {
                detectedCount++;
                detectedVariants.add(variant);
            } else {
                missedCount++;
                missedVariants.add(variant);
            }
        }

        return new BattleResult(
            target,
            allVariants.size(),
            detectedCount,
            missedCount,
            missedVariants,
            detectedVariants
        );
    }

    public void printReport(BattleResult result, String target) {
        double rate = result.detectionRate();
        double missedRate = 100.0 - rate;

        System.out.println("╔════════════════════════════════════════╗");
        System.out.println("║       Battle Report: " + String.format("%-18s", target) + "║");
        System.out.println("╚════════════════════════════════════════╝");
        System.out.println();
        System.out.println("⚔️  攻撃者が生成: " + result.totalAttacks() + " 件のフィッシング・バリアント");
        System.out.printf("🛡️  防御側が識別: %d 件 (%.1f%%)\n", result.detectedCount(), rate);
        System.out.printf("⚠️  漏れ件数:   %d 件 (%.1f%%)\n", result.missedCount(), missedRate);
        System.out.println();
        System.out.println("📊 検出率プログレスバー:");
        printProgressBar(rate);
        System.out.println();

        System.out.println("✅ 識別済み攻撃（サンプル5件）:");
        int count = 0;
        for (String variant : result.detectedVariants()) {
            if (count >= 5) break;
            DetectionResult dr = detector.check(variant);
            System.out.printf("  %s %-20s → %s (score: %d)%s\n", 
                dr.riskLevel().getIcon(), variant, dr.riskLevel().name(), dr.score(), RiskLevel.reset());
            count++;
        }
        System.out.println();

        System.out.println("❌ 漏れた攻撃（全件）:");
        if (result.missedVariants().isEmpty()) {
            System.out.println("  （漏れなし）");
        } else {
            for (String variant : result.missedVariants()) {
                DetectionResult dr = detector.check(variant);
                System.out.printf("  ⭕ %-20s → \u001B[32mGREEN\u001B[0m (score: %d)  ← 应该被检测!\n", 
                    variant, dr.score());
            }
        }
        System.out.println();
        System.out.println("💡 分析:");
        System.out.println("漏れ事例は編集距離 ≥ 2 のバリアントが多い。");
        System.out.println("今後の改善: 視覚的類似度（0/o, l/1 など）の特別処理を検討。");
    }

    private void printProgressBar(double percentage) {
        int width = 20;
        int filled = (int) (percentage / 100.0 * width);
        System.out.print("[");
        for (int i = 0; i < width; i++) {
            if (i < filled) System.out.print("█");
            else System.out.print("░");
        }
        System.out.printf("] %.1f%%\n", percentage);
    }

    public static void main(String[] args) {
        BattleRunner runner = withDefaults();
        String target = "amazon.co.jp";
        BattleResult result = runner.run(target, 4);
        runner.printReport(result, target);
    }
}
