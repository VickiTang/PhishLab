package com.phishlab;

import com.phishlab.generator.PhishingDomainGenerator;
import com.phishlab.hash.HashUtils;
import com.phishlab.hash.HashBlocklist;
import com.phishlab.detector.DomainCheckService;
import com.phishlab.battle.BattleRunner;
import com.phishlab.battle.BattleResult;
import com.phishlab.generator.BecEmail;
import com.phishlab.generator.BecEmailGenerator;
import com.phishlab.detector.BecPatternService;
import com.phishlab.detector.DetectionResult;
import com.phishlab.web.WebServer;
import java.util.List;
import java.util.Collections;

public class PhishLabApp {
    public static void main(String[] args) {
        if (args.length == 0) {
            runDefaultDemo();
        } else if (args[0].equals("demo")) {
            InteractiveDemo.run();
        } else if (args[0].equals("web")) {
            try {
                WebServer.start(8080);
            } catch (Exception e) {
                System.err.println("WebServer の起動に失敗しました: " + e.getMessage());
                System.exit(1);
            }
        } else if (args[0].equals("help") || args[0].equals("--help")) {
            printHelp();
        } else {
            printHelp();
        }
    }

    private static void printHelp() {
        System.out.println("使用方法:");
        System.out.println("  java -jar phishlab.jar          全モジュールデモ");
        System.out.println("  java -jar phishlab.jar demo     プレゼン用デモ");
        System.out.println("  java -jar phishlab.jar web      Webブラウザでデモ");
        System.out.println("  java -jar phishlab.jar help     ヘルプ表示");
    }

    private static void runDefaultDemo() {
        System.out.println("PhishLab v0.1 - Phishing Analysis Lab");
        System.out.println();

        // [Generator Demo]
        PhishingDomainGenerator generator = new PhishingDomainGenerator();
        String target = "amazon.co.jp";
        List<String> variants = generator.typoSquat(target);

        System.out.println("[Generator Demo]");
        System.out.println("Target: " + target);
        System.out.println();
        System.out.println("Generated phishing variants:");
        for (int i = 0; i < variants.size(); i++) {
            System.out.println("  " + (i + 1) + ". " + variants.get(i));
        }
        System.out.println();

        // [Hash Demo]
        System.out.println("[Hash Demo]");
        HashUtils.demo();
        System.out.println();

        // [Blocklist Demo]
        System.out.println("[Blocklist Demo]");
        HashBlocklist.demo();
        System.out.println();

        // [Detector Demo]
        System.out.println("[Detector Demo]");
        DomainCheckService.demo();
        System.out.println();

        // [Battle Demo]
        System.out.println("[Battle Demo]");
        BattleRunner runner = BattleRunner.withDefaults();
        BattleResult result = runner.run(target, 4);
        runner.printReport(result, target);
        System.out.println();

        // [BEC Demo]
        System.out.println("╔════════════════════════════════════════╗");
        System.out.println("║  BEC (Business Email Compromise) Demo  ║");
        System.out.println("╚════════════════════════════════════════╝");
        System.out.println();
        System.out.println("📌 攻撃者は社長/部長なりすまして偽メールを送信。");
        System.out.println("   防御者は複数の指標を組み合わせて検出する。");
        System.out.println();

        BecEmailGenerator becGenerator = new BecEmailGenerator(42);
        BecEmail becEmail = becGenerator.generate();
        BecPatternService becService = BecPatternService.withDefaults();

        System.out.println("─────── 生成された BEC メール ───────");
        System.out.println();
        System.out.println("差出人: " + becEmail.fromName() + " <" + becEmail.fullEmail() + ">");
        System.out.println("件名: " + becEmail.subject());
        System.out.println(becEmail.body());
        System.out.println();

        System.out.println("─────── 検出結果 ───────");
        System.out.println();
        DetectionResult becResult = becService.check(becEmail);
        printDetectionResult(becResult);
        System.out.println();

        System.out.println("─────── 对比: 正常メール ───────");
        System.out.println();
        BecEmail normalEmail = new BecEmail(
            "明日の会議資料について",
            "山田課長",
            "yourcompany.co.jp",
            "yamada@yourcompany.co.jp",
            "明日の定例会議の资料を共有します。ご確認ください。",
            "課長",
            Collections.emptyList()
        );
        System.out.println("差出人: " + normalEmail.fromName() + " <" + normalEmail.fullEmail() + ">");
        System.out.println("件名: " + normalEmail.subject());
        System.out.println();
        
        DetectionResult normalResult = becService.check(normalEmail);
        printDetectionResult(normalResult);
        System.out.println();
        System.out.println("💡 BEC 攻撃と正常メールが正確に区別された。");
    }

    private static void printDetectionResult(DetectionResult result) {
        System.out.println("📊 検出結果: " + result.riskLevel().getIcon() + " " + 
                           result.riskLevel().name() + " " + result.riskLevel().getLabel() + 
                           " (Score: " + result.score() + "/100)");
        System.out.println("📋 判定理由:");
        for (String reason : result.reasons()) {
            System.out.println("  - " + reason);
        }
    }
}
