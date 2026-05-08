package com.phishlab;

import com.phishlab.generator.PhishingDomainGenerator;
import com.phishlab.hash.HashUtils;
import com.phishlab.hash.HashBlocklist;
import com.phishlab.detector.DomainCheckService;
import com.phishlab.battle.BattleRunner;
import com.phishlab.battle.BattleResult;
import java.util.List;

public class PhishLabApp {
    public static void main(String[] args) {
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
    }
}
