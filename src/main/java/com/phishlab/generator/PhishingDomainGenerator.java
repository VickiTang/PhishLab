package com.phishlab.generator;

import java.util.*;

public class PhishingDomainGenerator {
    private Random random = new Random();
    private static final Map<Character, Character> REPLACEMENTS = new HashMap<>();
    private static final Map<Character, String> ADJACENT_KEYS = new HashMap<>();

    static {
        REPLACEMENTS.put('n', 'm');
        REPLACEMENTS.put('o', '0');
        REPLACEMENTS.put('i', '1');
        REPLACEMENTS.put('e', '3');
        REPLACEMENTS.put('a', '@');
        REPLACEMENTS.put('l', '1');
        REPLACEMENTS.put('s', '5');

        ADJACENT_KEYS.put('a', "qwsz");
        ADJACENT_KEYS.put('b', "vghn");
        ADJACENT_KEYS.put('c', "xdfv");
        ADJACENT_KEYS.put('d', "erfcx");
        ADJACENT_KEYS.put('e', "wsdrf");
        ADJACENT_KEYS.put('f', "rtgvc");
        ADJACENT_KEYS.put('g', "tyhbf");
        ADJACENT_KEYS.put('h', "yujng");
        ADJACENT_KEYS.put('i', "ujko");
        ADJACENT_KEYS.put('j', "uikmh");
        ADJACENT_KEYS.put('k', "iolmj");
        ADJACENT_KEYS.put('l', "kop");
        ADJACENT_KEYS.put('m', "njk");
        ADJACENT_KEYS.put('n', "bhjm");
        ADJACENT_KEYS.put('o', "iklp");
        ADJACENT_KEYS.put('p', "ol");
        ADJACENT_KEYS.put('q', "wa");
        ADJACENT_KEYS.put('r', "edft");
        ADJACENT_KEYS.put('s', "awedx");
        ADJACENT_KEYS.put('t', "rfgy");
        ADJACENT_KEYS.put('u', "yhji");
        ADJACENT_KEYS.put('v', "cfgb");
        ADJACENT_KEYS.put('w', "qeas");
        ADJACENT_KEYS.put('x', "zsdc");
        ADJACENT_KEYS.put('y', "tghu");
        ADJACENT_KEYS.put('z', "asx");
    }

    public void setSeed(long seed) {
        this.random.setSeed(seed);
    }

    public List<String> typoSquat(String domain) {
        int lastDotIndex = domain.indexOf('.');
        if (lastDotIndex == -1) return Collections.emptyList();

        String name = domain.substring(0, lastDotIndex);
        String tld = domain.substring(lastDotIndex);

        Set<String> variants = new HashSet<>();
        while (variants.size() < 5) {
            String variant = generateVariant(name);
            if (!variant.equals(name)) {
                variants.add(variant + tld);
            }
        }

        return new ArrayList<>(variants);
    }

    private String generateVariant(String name) {
        int strategy = random.nextInt(5);
        StringBuilder sb = new StringBuilder(name);

        switch (strategy) {
            case 0: // Replacement
                return replaceChar(name);
            case 1: // Swap
                return swapChars(name);
            case 2: // Deletion
                return deleteChar(name);
            case 3: // Repetition
                return repeatChar(name);
            case 4: // Insertion
                return insertChar(name);
            default:
                return name;
        }
    }

    private String replaceChar(String name) {
        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < name.length(); i++) {
            if (REPLACEMENTS.containsKey(name.charAt(i))) {
                indices.add(i);
            }
        }
        if (indices.isEmpty()) return swapChars(name); // Fallback

        int idx = indices.get(random.nextInt(indices.size()));
        char original = name.charAt(idx);
        char replaced = REPLACEMENTS.get(original);
        return name.substring(0, idx) + replaced + name.substring(idx + 1);
    }

    private String swapChars(String name) {
        if (name.length() < 2) return name;
        int idx = random.nextInt(name.length() - 1);
        char[] chars = name.toCharArray();
        char temp = chars[idx];
        chars[idx] = chars[idx + 1];
        chars[idx + 1] = temp;
        return new String(chars);
    }

    private String deleteChar(String name) {
        if (name.length() < 2) return name;
        int idx = random.nextInt(name.length());
        return new StringBuilder(name).deleteCharAt(idx).toString();
    }

    private String repeatChar(String name) {
        if (name.isEmpty()) return name;
        int idx = random.nextInt(name.length());
        return name.substring(0, idx) + name.charAt(idx) + name.substring(idx);
    }

    private String insertChar(String name) {
        if (name.isEmpty()) return name;
        int idx = random.nextInt(name.length());
        char c = name.charAt(idx);
        String adj = ADJACENT_KEYS.getOrDefault(Character.toLowerCase(c), "x");
        char insert = adj.charAt(random.nextInt(adj.length()));
        return name.substring(0, idx + 1) + insert + name.substring(idx + 1);
    }
}
