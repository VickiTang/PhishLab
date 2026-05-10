package com.phishlab.detector;

import com.phishlab.util.LevenshteinCalculator;
import java.util.*;

/**
 * HomoglyphLetterSwapChecker
 * 检测同形字攻击（homoglyph）和字母交换攻击（letter swap）
 */
public class HomoglyphLetterSwapChecker {

    private final Set<String> trustedBrandStrings;

    public HomoglyphLetterSwapChecker(Set<String> trustedBrands) {
        this.trustedBrandStrings = trustedBrands;
    }

    public static HomoglyphLetterSwapChecker withDefaults() {
        // 复用 BrandKeywordMatcher 里的品牌列表
        Set<String> brands = new HashSet<>(Arrays.asList(
            "amazon", "google", "microsoft", "apple", "netflix", "paypal",
            "github", "rakuten", "yahoo", "line", "twitter", "facebook",
            "mercari", "smbc", "mufg", "jcb", "visa", "mastercard",
            "yamato", "sagawa", "japanpost", "ana", "jal", "docomo",
            "softbank", "au", "yucho", "mizuho", "resona"
        ));
        return new HomoglyphLetterSwapChecker(brands);
    }

    public DetectionResult check(String domain) {
        if (domain == null || domain.isEmpty()) {
            return new DetectionResult(domain, RiskLevel.GREEN, 0, Collections.singletonList("ドメインが空です"));
        }

        String target = domain.trim().toLowerCase();
        String mainName = extractMainName(target);
        String normalized = normalize(mainName);

        for (String brand : trustedBrandStrings) {
            boolean isHomoglyphHit = false;
            boolean isLetterSwapHit = false;

            // Only check if it's not the exact brand already
            if (!mainName.equals(brand)) {
                // 1. Homoglyph check: normalized version is very close to brand (levenshtein <= 1)
                int distance = LevenshteinCalculator.distance(normalized, brand);
                if (distance <= 1) {
                    isHomoglyphHit = true;
                }

                // 2. Letter swap check: on normalized string
                if (isLetterSwap(normalized, brand)) {
                    isLetterSwapHit = true;
                }
            }

            if (isHomoglyphHit) {
                return new DetectionResult(
                    target,
                    RiskLevel.RED,
                    80,
                    Collections.singletonList("ホモグリフ攻撃の可能性（" + brand + " の数字/同形字置換）")
                );
            }

            if (isLetterSwapHit) {
                return new DetectionResult(
                    target,
                    RiskLevel.RED,
                    80,
                    Collections.singletonList("文字入替攻撃の可能性（" + brand + " の文字位置交換）")
                );
            }
        }

        return new DetectionResult(
            target,
            RiskLevel.GREEN,
            0,
            Collections.singletonList("ホモグリフ・文字入替攻撃は検出されません")
        );
    }

    private String extractMainName(String domain) {
        // 简单做法: 取第一个点之前的部分，或者取最长的非 TLD 部分
        // 这里采用取第一个点之前的部分，或者如果包含 '-' 则取完整部分
        int firstDot = domain.indexOf('.');
        if (firstDot == -1) return domain;
        
        String candidate = domain.substring(0, firstDot);
        
        // 处理 co.jp 这种情况，如果 candidate 太短可能是误判，但这里按要求简单处理
        return candidate;
    }

    private String normalize(String s) {
        Map<Character, Character> homoglyphMap = new HashMap<>();
        homoglyphMap.put('0', 'o');
        homoglyphMap.put('1', 'l');
        homoglyphMap.put('3', 'e');
        homoglyphMap.put('4', 'a');
        homoglyphMap.put('5', 's');
        homoglyphMap.put('6', 'b');
        homoglyphMap.put('7', 't');
        homoglyphMap.put('9', 'g');
        homoglyphMap.put('@', 'a');
        homoglyphMap.put('$', 's');

        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            sb.append(homoglyphMap.getOrDefault(c, c));
        }
        return sb.toString();
    }

    private boolean isLetterSwap(String input, String brand) {
        if (input.length() != brand.length()) {
            return false;
        }

        List<Integer> diffIndices = new ArrayList<>();
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) != brand.charAt(i)) {
                diffIndices.add(i);
            }
        }

        if (diffIndices.size() != 2) {
            return false;
        }

        int i = diffIndices.get(0);
        int j = diffIndices.get(1);

        return input.charAt(i) == brand.charAt(j) && input.charAt(j) == brand.charAt(i);
    }

    public static void main(String[] args) {
        HomoglyphLetterSwapChecker checker = withDefaults();

        System.out.println("===== Homoglyph + Letter Swap Checker デモ =====");
        System.out.println();

        String[] testCases = {
            "jbc.co.jp",
            "amaz0n.co.jp",
            "paypa1.com",
            "gogole.com",
            "amazon.co.jp",
            "example.org"
        };

        String[] expectations = {
            "RED (LETTER_SWAP, jcb)",
            "RED (HOMOGLYPH, amazon)",
            "RED (HOMOGLYPH, paypal)",
            "RED (LETTER_SWAP, google)",
            "GREEN",
            "GREEN"
        };

        for (int i = 0; i < testCases.length; i++) {
            String domain = testCases[i];
            System.out.println("テスト" + (i + 1) + ": " + domain);
            System.out.println("  期待: " + expectations[i]);
            DetectionResult result = checker.check(domain);
            System.out.print(result.toString());
            System.out.println();
        }
    }
}
