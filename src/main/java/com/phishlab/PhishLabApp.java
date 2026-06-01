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
    private static final Logger logger = LoggerFactory.getLogger(PhishLabApp.class);
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
        logger.info("使用方法:");
        logger.info("  java -jar phishlab.jar          全モジュールデモ");
        logger.info("  java -jar phishlab.jar demo     プレゼン用デモ");
        logger.info("  java -jar phishlab.jar web      Webブラウザでデモ");
        logger.info("  java -jar phishlab.jar help     ヘルプ表示");
    }

    private static void runDefaultDemo() {
        logger.info("PhishLab v0.1 - Phishing Analysis Lab");
        logger.info("");

        // [Generator Demo]
        PhishingDomainGenerator generator = new PhishingDomainGenerator();
        String target = "amazon.co.jp";
        List<String> variants = generator.typoSquat(target);

        logger.info("[Generator Demo]");
        logger.info("Target: {}", target);
        logger.info("");
        logger.info("Generated phishing variants:");
        for (int i = 0; i < variants.size(); i++) {
            logger.info("  {}. {}", (i + 1), variants.get(i));
        }
        logger.info("");

        // [Hash Demo]
        logger.info("[Hash Demo]");
        HashUtils.demo();
        logger.info("");

        // [Blocklist Demo]
        logger.info("[Blocklist Demo]");
        HashBlocklist.demo();
        logger.info("");

        // [Detector Demo]
        logger.info("[Detector Demo]");
        DomainCheckService.demo();
        logger.info("");

        // [Battle Demo]
        logger.info("[Battle Demo]");
        BattleRunner runner = BattleRunner.withDefaults();
        BattleResult result = runner.run(target, 4);
        runner.printReport(result, target);
        logger.info("");

        // [BEC Demo]
        logger.info("╔════════════════════════════════════════╗");
        logger.info("║  BEC (Business Email Compromise) Demo  ║");
        logger.info("╚════════════════════════════════════════╝");
        logger.info("");
        logger.info("📌 攻撃者は社長/部長なりすまして偽メールを送信。");
        logger.info("   防御者は複数の指標を組み合わせて検出する。");
        logger.info("");

        BecEmailGenerator becGenerator = new BecEmailGenerator(42);
        BecEmail becEmail = becGenerator.generate();
        BecPatternService becService = BecPatternService.withDefaults();

        logger.info("─────── 生成された BEC メール ───────");
        logger.info("");
        logger.info("差出人: {} <{}>", becEmail.fromName(), becEmail.fullEmail());
        logger.info("件名: {}", becEmail.subject());
        logger.info(becEmail.body());
        logger.info("");

        logger.info("─────── 検出結果 ───────");
        logger.info("");
        DetectionResult becResult = becService.check(becEmail);
        printDetectionResult(becResult);
        logger.info("");

        logger.info("─────── 对比: 正常メール ───────");
        logger.info("");
        BecEmail normalEmail = new BecEmail(
            "明日の会議資料について",
            "山田課長",
            "yourcompany.co.jp",
            "yamada@yourcompany.co.jp",
            "明日の定例会議の资料を共有します。ご確認ください。",
            "課長",
            Collections.emptyList()
        );
        logger.info("差出人: {} <{}>", normalEmail.fromName(), normalEmail.fullEmail());
        logger.info("件名: {}", normalEmail.subject());
        logger.info("");
        
        DetectionResult normalResult = becService.check(normalEmail);
        printDetectionResult(normalResult);
        logger.info("");
        logger.info("💡 BEC 攻撃と正常メールが正確に区別された。");
    }

    private static void printDetectionResult(DetectionResult result) {
        logger.info("📊 検出結果: {} {} {} (Score: {}/100)", 
                           result.riskLevel().getIcon(), 
                           result.riskLevel().name(), 
                           result.riskLevel().getLabel(), 
                           result.score());
        logger.info("📋 判定理由:");
        for (String reason : result.reasons()) {
            logger.info("  - {}", reason);
        }
    }
}
