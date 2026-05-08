package com.phishlab.util;

public class LevenshteinCalculator {

    /**
     * 计算两个字符串之间的 Levenshtein 编辑距离
     * @param a 字符串 a
     * @param b 字符串 b
     * @return 最少编辑步数
     * @throws IllegalArgumentException 如果任一参数为 null
     */
    public static int distance(String a, String b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Strings must not be null");
        }

        int n = a.length();
        int m = b.length();

        // 处理空字符串的情况
        if (n == 0) return m;
        if (m == 0) return n;

        // dp[i][j] 表示 a 的前 i 个字符到 b 的前 j 个字符的编辑距离
        int[][] dp = new int[n + 1][m + 1];

        // 状态初始化：从空字符串变换到目标长度所需的删除/插入次数
        for (int i = 0; i <= n; i++) dp[i][0] = i;
        for (int j = 0; j <= m; j++) dp[0][j] = j;

        // 状态转移
        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= m; j++) {
                // 如果当前字符相同，不需要操作
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;

                dp[i][j] = Math.min(
                    Math.min(
                        dp[i - 1][j] + 1,    // 删除 a[i-1]
                        dp[i][j - 1] + 1     // 插入 b[j-1]
                    ),
                    dp[i - 1][j - 1] + cost  // 替换
                );
            }
        }

        return dp[n][m];
    }

    /**
     * 计算两个字符串之间的相似度 [0.0, 1.0]
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
        int dist = distance(a, b);
        double sim = similarity(a, b);
        System.out.println("测试: \"" + a + "\" vs \"" + b + "\"");
        System.out.println("  编辑距离: " + dist);
        System.out.printf("  相似度:   %.1f%%\n", sim * 100);
        System.out.println("  说明: " + description);
        System.out.println();
    }

    public static void main(String[] args) {
        System.out.println("===== Levenshtein 编辑距离演示 =====");
        System.out.println();

        test("amazon", "amazon", "完全相同");
        test("amazon", "amazom", "1 个字符替换 (典型 typo 钓鱼)");
        test("amazon", "amzaon", "2 个字符交换 (轻度变异)");
        test("amazon", "google", "完全不同");
        test("amazon.co.jp", "arnazon.co.jp", "域名级别的钓鱼检测");
    }
}
