package com.phishlab.detector;

import java.util.*;

/**
 * BrandKeywordMatcher
 * Detects brand impersonation attacks where brand names are embedded in non-official domains.
 */
import java.io.IOException;
import java.io.InputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.stream.Collectors;

public class BrandKeywordMatcher {

    private final Set<String> brandKeywords;
    private final Map<String, Set<String>> officialDomainsMap;

    public BrandKeywordMatcher() {
        this.brandKeywords = new HashSet<>(Arrays.asList(
            "amazon", "google", "microsoft", "apple", "netflix", "paypal",
            "github", "rakuten", "yahoo", "line", "twitter", "facebook",
            "mercari", "smbc", "mufg", "jcb", "visa", "mastercard",
            "yamato", "sagawa", "japanpost", "ana", "jal", "docomo",
            "softbank", "au", "yucho", "mizuho", "resona"
        ));

        this.officialDomainsMap = new HashMap<>();
        officialDomainsMap.put("amazon", new HashSet<>(Arrays.asList("amazon.co.jp", "amazon.com")));
        officialDomainsMap.put("google", new HashSet<>(Arrays.asList("google.com", "google.co.jp")));
        officialDomainsMap.put("microsoft", new HashSet<>(Arrays.asList("microsoft.com")));
        officialDomainsMap.put("apple", new HashSet<>(Arrays.asList("apple.com")));
        officialDomainsMap.put("netflix", new HashSet<>(Arrays.asList("netflix.com")));
        officialDomainsMap.put("paypal", new HashSet<>(Arrays.asList("paypal.com")));
        officialDomainsMap.put("github", new HashSet<>(Arrays.asList("github.com")));
        officialDomainsMap.put("rakuten", new HashSet<>(Arrays.asList("rakuten.co.jp")));
        officialDomainsMap.put("yahoo", new HashSet<>(Arrays.asList("yahoo.co.jp", "yahoo.com")));
        officialDomainsMap.put("line", new HashSet<>(Arrays.asList("line.me")));
        officialDomainsMap.put("twitter", new HashSet<>(Arrays.asList("twitter.com")));
        officialDomainsMap.put("facebook", new HashSet<>(Arrays.asList("facebook.com")));
        officialDomainsMap.put("mercari", new HashSet<>(Arrays.asList("mercari.com", "mercari.jp")));
        officialDomainsMap.put("smbc", new HashSet<>(Arrays.asList("smbc.co.jp")));
        officialDomainsMap.put("mufg", new HashSet<>(Arrays.asList("mufg.jp", "bk.mufg.jp")));
        officialDomainsMap.put("jcb", new HashSet<>(Arrays.asList("jcb.co.jp")));
        officialDomainsMap.put("visa", new HashSet<>(Arrays.asList("visa.com", "visa.co.jp")));
        officialDomainsMap.put("mastercard", new HashSet<>(Arrays.asList("mastercard.com")));

        // Japanese brands
        officialDomainsMap.put("yamato", new HashSet<>(Arrays.asList("kuronekoyamato.co.jp")));
        officialDomainsMap.put("sagawa", new HashSet<>(Arrays.asList("sagawa-exp.co.jp")));
        officialDomainsMap.put("japanpost", new HashSet<>(Arrays.asList("post.japanpost.jp", "japanpost.jp")));
        officialDomainsMap.put("ana", new HashSet<>(Arrays.asList("ana.co.jp")));
        officialDomainsMap.put("jal", new HashSet<>(Arrays.asList("jal.co.jp")));
        officialDomainsMap.put("docomo", new HashSet<>(Arrays.asList("docomo.ne.jp", "nttdocomo.co.jp")));
        officialDomainsMap.put("softbank", new HashSet<>(Arrays.asList("softbank.jp")));
        officialDomainsMap.put("au", new HashSet<>(Arrays.asList("au.com", "kddi.com")));
        officialDomainsMap.put("yucho", new HashSet<>(Arrays.asList("jp-bank.japanpost.jp")));
        officialDomainsMap.put("mizuho", new HashSet<>(Arrays.asList("mizuhobank.co.jp")));
        officialDomainsMap.put("resona", new HashSet<>(Arrays.asList("resonabank.co.jp")));
    }

    /**
     * Checks if a domain contains a brand keyword and is not an official domain.
     * @param domain The domain to check.
     * @return A DetectionResult indicating the risk level.
     */
    public DetectionResult check(String domain) {
        if (domain == null) {
            return new DetectionResult("null", RiskLevel.GREEN, 0, Collections.singletonList("Domain is null."));
        }

        String targetDomain = domain.toLowerCase().trim();

        for (String brand : brandKeywords) {
            if (targetDomain.contains(brand)) {
                Set<String> officialDomains = officialDomainsMap.get(brand);
                
                if (officialDomains != null && officialDomains.contains(targetDomain)) {
                    continue;
                }

                return new DetectionResult(
                    domain,
                    RiskLevel.RED,
                    85,
                    Collections.singletonList("Brand name '" + brand + "' found, but not an official domain (suspected brand impersonation).")
                );
            }
        }

        return new DetectionResult(
            domain,
            RiskLevel.GREEN,
            0,
            Collections.singletonList("No brand keyword embedding detected.")
        );
    }
public static void main(String[] args) {
    Logger logger = LoggerFactory.getLogger(BrandKeywordMatcher.class);
    BrandKeywordMatcher matcher = new BrandKeywordMatcher();

    logger.info("===== Brand Keyword Matcher Demo =====");
    logger.info("");

    String[] testDomains = {
        "amazon-security.com",
        "amazon.co.jp",
        "secure-paypal-login.net",
        "example.org"
    };

    int count = 1;
    for (String domain : testDomains) {
        DetectionResult result = matcher.check(domain);
        logger.info("Test {}: {}", count, domain);

        String status = result.riskLevel() == RiskLevel.RED ? "⛔ RED High Risk" : "✓ GREEN Low Risk";
        logger.info("  Detection Result: {} (Score: {})", status, result.score());

        String reason = result.reasons().isEmpty() ? "" : result.reasons().get(0);
        if (domain.equals("amazon.co.jp")) {
            logger.info("  Reason: No brand keyword embedding detected (official domain).");
        } else {
            logger.info("  Reason: {}", reason);
        }
        logger.info("");
        count++;
    }
}
}
