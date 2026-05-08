package com.phishlab.detector;

import java.util.HashSet;
import java.util.Set;
import java.util.Arrays;
import java.util.Collections;

public class SuspiciousTldChecker {
    private final Set<String> suspiciousTlds;

    public SuspiciousTldChecker() {
        this.suspiciousTlds = new HashSet<>(Arrays.asList(
            ".tk", ".ml", ".ga", ".cf", ".gq",
            ".top", ".click", ".work", ".xyz", ".loan", ".racing", ".date",
            ".country", ".kim", ".cricket", ".accountant", ".science"
        ));
    }

    public DetectionResult check(String domain) {
        String lowerDomain = domain.toLowerCase();
        for (String tld : suspiciousTlds) {
            if (lowerDomain.endsWith(tld)) {
                return new DetectionResult(domain, RiskLevel.YELLOW, 50, 
                    Collections.singletonList("疑わしいTLD (" + tld + ") - 無料/低価格TLDによる仿冒の可能性"));
            }
        }
        return new DetectionResult(domain, RiskLevel.GREEN, 0, 
            Collections.singletonList("TLDは正常範囲内"));
    }

    public static void main(String[] args) {
        SuspiciousTldChecker checker = new SuspiciousTldChecker();
        String[] testDomains = {"amazon.tk", "amazon.top", "github.com", "paypal.xyz"};
        
        for (String domain : testDomains) {
            DetectionResult result = checker.check(domain);
            System.out.printf("Domain: %-15s | Level: %-8s | Score: %d | Reason: %s%n", 
                domain, result.riskLevel(), result.score(), result.reasons().get(0));
        }
    }
}
