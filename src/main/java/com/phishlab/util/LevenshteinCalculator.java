package com.phishlab.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LevenshteinCalculator {

    /**
     * Calculates the Levenshtein edit distance between two strings.
     * @param a String a
     * @param b String b
     * @return The minimum number of edits required.
     * @throws IllegalArgumentException if either parameter is null.
     */
    public static int distance(String a, String b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Strings must not be null");
        }

        int n = a.length();
        int m = b.length();

        if (n == 0) return m;
        if (m == 0) return n;

        int[][] dp = new int[n + 1][m + 1];

        for (int i = 0; i <= n; i++) dp[i][0] = i;
        for (int j = 0; j <= m; j++) dp[0][j] = j;

        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= m; j++) {
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;

                dp[i][j] = Math.min(
                    Math.min(
                        dp[i - 1][j] + 1,    // Deletion
                        dp[i][j - 1] + 1     // Insertion
                    ),
                    dp[i - 1][j - 1] + cost  // Substitution
                );
            }
        }

        return dp[n][m];
    }

    /**
     * Calculates the similarity between two strings [0.0, 1.0] based on Levenshtein distance.
     */
    public static double similarity(String a, String b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Strings must not be null");
        }
        if (a.isEmpty() && b.isEmpty()) {
            return 1.0;
        }

        int dist = distance(a, b);
        int maxLen = Math.max(a.length(), b.length());
        return 1.0 - (double) dist / maxLen;
    }

    private static void test(String a, String b, String description) {
        Logger logger = LoggerFactory.getLogger(LevenshteinCalculator.class);
        int dist = distance(a, b);
        double sim = similarity(a, b);
        logger.info("Test: \"{}\" vs \"{}"", a, b);
        logger.info("  Edit Distance: {}", dist);
        logger.info("  Similarity:   {:.1f}%", sim * 100);
        logger.info("  Description: {}", description);
        logger.info("");
    }

    public static void main(String[] args) {
        Logger logger = LoggerFactory.getLogger(LevenshteinCalculator.class);
        logger.info("===== Levenshtein Edit Distance Demo =====");
        logger.info("");

        test("amazon", "amazon", "Identical");
        test("amazon", "amazom", "1 character substitution (typical typo phishing)");
        test("amazon", "amzaon", "2 character swap (slight variation)");
        test("amazon", "google", "Completely different");
        test("amazon.co.jp", "arnazon.co.jp", "Domain-level phishing detection");
    }
}
