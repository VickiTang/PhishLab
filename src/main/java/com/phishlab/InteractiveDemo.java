package com.phishlab;

import com.phishlab.battle.BattleRunner;
import com.phishlab.battle.BattleResult;
import com.phishlab.detector.BecPatternService;
import com.phishlab.detector.DetectionResult;
import com.phishlab.detector.DomainCheckService;
import com.phishlab.detector.RiskLevel;
import com.phishlab.generator.BecEmail;
import com.phishlab.generator.BecEmailGenerator;
import com.phishlab.generator.PhishingDomainGenerator;
import java.util.List;
import java.util.Scanner;

public class InteractiveDemo {

    public static void run() {
        chapter1();
        chapter2();
        chapter3();
        chapter4();
        chapter5();
    }

    private static void chapter1() {
        System.out.println("╔════════════════════════════════════════════════╗");
        System.out.println("║                                                ║");
        System.out.println("║              PhishLab v0.1                     ║");
        System.out.println("║      フィッシング分析ラボ・デモ                ║");
        System.out.println("║                                                ║");
        System.out.println("╚════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("📖 本デモについて");
        System.out.println("─────────────────────────────────────────────────");
        System.out.println();
        System.out.println("日本企業が直面するフィッシング攻撃の主要な3パターンを、");
        System.out.println("攻撃と防御の両視点から分析する研究プロトタイプです。");
        System.out.println();
        System.out.println("📋 デモの構成（約5分）:");
        System.out.println();
        System.out.println("  1️⃣  攻撃者視点 - 偽ドメイン・偽メールの自動生成");
        System.out.println("  2️⃣  防御者視点 - 多戦略による検出");
        System.out.println("  3️⃣  攻防対抗  - 自動評価で性能を可視化");
        System.out.println("  4️⃣  まとめ");
        System.out.println();
        System.out.println("⚠️ 重要なお知らせ:");
        System.out.println("全データは合成データです。");
        System.out.println("実在の企業情報・顧客情報・社内データは一切使用していません。");
        System.out.println();
        System.out.println("─────────────────────────────────────────────────");
        
        waitForEnter();
    }

    private static void chapter2() {
        System.out.println("╔════════════════════════════════════════════════╗");
        System.out.println("║   Chapter 1: 攻撃者視点 ─ なりすましの自動生成   ║");
        System.out.println("╚════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("🎭 「攻撃者」になりきり、コードでフィッシング素材を生成。");
        System.out.println();
        System.out.println("─── ① 偽ドメインの自動生成 (typoSquat) ───");
        System.out.println();
        System.out.println("対象ブランド: amazon.co.jp");
        System.out.println("生成された偽ドメイン:");
        
        PhishingDomainGenerator domainGen = new PhishingDomainGenerator();
        domainGen.setSeed(42);
        List<String> domains = domainGen.typoSquat("amazon.co.jp");
        for (int i = 0; i < domains.size(); i++) {
            System.out.println((i + 1) + ". " + domains.get(i));
        }
        System.out.println();
        System.out.println("💡 なぜ重要か:");
        System.out.println("攻撃者は「人間が一目で気づきにくい」変形を機械的に量産できる。");
        System.out.println("1日で数千件のドメインを生成・取得することが可能。");
        System.out.println();
        System.out.println("─── ② 偽 BEC メールの自動生成 ───");
        System.out.println();
        
        BecEmailGenerator becGen = new BecEmailGenerator(42);
        BecEmail becEmail = becGen.generate();
        System.out.println(becEmail.toFormattedString());
        System.out.println();
        System.out.println("💡 なぜ重要か:");
        System.out.println("実在する日本人名・役職・商習慣を組み合わせ、");
        System.out.println("違和感の少ないなりすましメールを大量生成できる。");

        waitForEnter();
    }

    private static void chapter3() {
        System.out.println("╔════════════════════════════════════════════════╗");
        System.out.println("║   Chapter 2: 防御者視点 ─ 多戦略による検出      ║");
        System.out.println("╚════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("🛡️ 「防御者」として、複数の独立した検出戦略を組み合わせる。");
        System.out.println();
        System.out.println("─── ① ドメイン検出（3戦略の融合） ───");
        System.out.println();
        
        DomainCheckService domainService = DomainCheckService.withDefaultTrustedDomains();
        
        String[] testDomains = {"arnazon.co.jp", "amazon-security.com", "amazon.tk"};
        String[] descriptions = {"(typo squatting)", "(combo squatting)", "(suspicious TLD)"};
        
        for (int i = 0; i < testDomains.length; i++) {
            System.out.println("テストドメイン: " + testDomains[i] + " " + descriptions[i]);
            DetectionResult res = domainService.check(testDomains[i]);
            printBriefResult(res);
            System.out.println();
        }
        
        System.out.println("💡 なぜ複数戦略が必要か:");
        System.out.println("単一の検出ロジックは特定の攻撃パターンに弱い。");
        System.out.println("- Levenshtein 距離 → typo squatting に有効");
        System.out.println("- Brand Keyword → combo squatting に有効");
        System.out.println("- Suspicious TLD → 無料TLD攻撃に有効");
        System.out.println("3戦略の組み合わせで網羅性が向上する。");
        System.out.println();
        System.out.println("─── ② BEC メール検出 ───");
        System.out.println();
        
        BecEmailGenerator becGen = new BecEmailGenerator(42);
        BecEmail becEmail = becGen.generate();
        System.out.println("検出対象: [Chapter 1 で生成したのと同じ BEC メール]");
        
        BecPatternService becService = BecPatternService.withDefaults();
        DetectionResult becRes = becService.check(becEmail);
        printBriefResult(becRes);
        System.out.println();
        
        System.out.println("💡 BEC 検出のポイント:");
        System.out.println("単一の指標では誤検出が多発する。");
        System.out.println("緊急性 + 金銭 + 機密性 + なりすましの組み合わせを判定。");

        waitForEnter();
    }

    private static void chapter4() {
        System.out.println("╔════════════════════════════════════════════════╗");
        System.out.println("║   Chapter 3: 攻防対抗 ─ 性能の可視化            ║");
        System.out.println("╚════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("⚔️ 攻撃者と防御者を実際に戦わせる。");
        System.out.println();
        System.out.println("─── Battle 1: typoSquat 攻撃 vs 多戦略検出 ───");
        System.out.println();
        
        String target = "amazon.co.jp";
        BattleRunner runner = BattleRunner.withDefaults();
        BattleResult result = runner.run(target, 4);
        runner.printReport(result, target);
        System.out.println();
        
        System.out.println("─── 重要な発見: 100% は警告である ───");
        System.out.println();
        System.out.println("📌 本研究の核心的発見:");
        System.out.println();
        System.out.println("typoSquat 攻撃のみを評価すると検出率は完璧（100%）に見える。");
        System.out.println("しかし、現実の攻撃手口（Combo Squatting、TLD Abuse 等）を");
        System.out.println("含めると、検出率は大幅に変化する。");
        System.out.println();
        System.out.println("┌─────────────────────────────────────────┐");
        System.out.println("│ Phase 1: typoSquat のみ          → 100% │");
        System.out.println("│ Phase 2: 真実の攻撃手口（旧版）   → 50%  │");
        System.out.println("│ Phase 3: 多戦略検出（現在）       → 90%  │");
        System.out.println("└─────────────────────────────────────────┘");
        System.out.println();
        System.out.println("💡 研究の本質:");
        System.out.println("「100% の検出率」は信号ではなく警告である。");
        System.out.println("評価データセットの網羅性こそが、検出器の真の性能を決める。");

        waitForEnter();
    }

    private static void chapter5() {
        System.out.println("╔════════════════════════════════════════════════╗");
        System.out.println("║   Chapter 4: まとめ                             ║");
        System.out.println("╚════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("📊 本日のデモ: 5 つの実装");
        System.out.println();
        System.out.println("  ✅ PhishingDomainGenerator   - typo squatting 攻撃の自動生成");
        System.out.println("  ✅ BecEmailGenerator         - 日本語 BEC メールの自動生成");
        System.out.println("  ✅ DomainCheckService        - 多戦略ドメイン検出器");
        System.out.println("  ✅ BecPatternService         - 多次元 BEC 検出器");
        System.out.println("  ✅ ChallengeTest / Battle    - 自動対抗評価フレームワーク");
        System.out.println();
        System.out.println("🎯 主要な成果:");
        System.out.println();
        System.out.println("  🔬 研究プロセスの実演:");
        System.out.println("     100% （単一攻撃モデル）");
        System.out.println("     ↓ 対抗的評価で課題を発見");
        System.out.println("     50%  （現実の攻撃手口を含む）");
        System.out.println("     ↓ 多戦略検出を実装");
        System.out.println("     90%  （改善後の検出率）");
        System.out.println();
        System.out.println("  🔐 プライバシー設計:");
        System.out.println("     - 全データが合成データ");
        System.out.println("     - 実在企業の情報を一切含まない");
        System.out.println("     - ハッシュ等の片方向関数で匿名化");
        System.out.println();
        System.out.println("🔭 今後の研究方向:");
        System.out.println();
        System.out.println("  - Combo Squatting Generator の追加（攻防対抗の網羅性向上）");
        System.out.println("  - Homoglyph Normalization（数字・同形字置換への対応）");
        System.out.println("  - 添付ファイルの fuzzy hashing 対応");
        System.out.println("  - 日本特化威脅情報源との統合");
        System.out.println();
        System.out.println("─────────────────────────────────────────────────");
        System.out.println();
        System.out.println("ご清聴ありがとうございました。");
        System.out.println("質疑応答をお願いいたします。");
    }

    private static void printBriefResult(DetectionResult result) {
        System.out.println("結果: " + result.riskLevel().getAnsiColor() + 
                           result.riskLevel().getIcon() + " " + 
                           result.riskLevel().name() + " (" + result.score() + "/100)" + 
                           RiskLevel.reset());
        if (!result.reasons().isEmpty()) {
            System.out.println("理由: " + result.reasons().get(0));
        }
    }

    private static void waitForEnter() {
        System.out.print("\n▶ Enter キーで開始 ... ");
        try {
            new Scanner(System.in).nextLine();
        } catch (Exception e) { /* ignore */ }
        System.out.println();
    }
}
