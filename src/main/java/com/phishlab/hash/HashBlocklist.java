package com.phishlab.hash;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class HashBlocklist {
    private final Set<String> blocklist;

    public HashBlocklist() {
        this.blocklist = new HashSet<>();
    }

    public HashBlocklist(Collection<String> hashes) {
        this.blocklist = hashes.stream()
                .map(String::toLowerCase)
                .map(String::trim)
                .collect(Collectors.toSet());
    }

    public void addHash(String hash) {
        if (hash != null) {
            blocklist.add(hash.trim().toLowerCase());
        }
    }

    public boolean contains(String hash) {
        return hash != null && blocklist.contains(hash.trim().toLowerCase());
    }

    public int size() {
        return blocklist.size();
    }

    public ScanResult scan(Path filePath) throws IOException {
        String hash = HashUtils.sha256OfFile(filePath);
        String fileName = filePath.getFileName().toString();
        
        if (contains(hash)) {
            return new ScanResult(fileName, hash, true, "⚠️  MALICIOUS - 既知の悪意あるファイル");
        } else {
            return new ScanResult(fileName, hash, false, "✓  CLEAN - 既知の脅威は検出されません");
        }
    }

    public static HashBlocklist fromFile(Path file) throws IOException {
        List<String> lines = Files.readAllLines(file);
        Set<String> hashes = lines.stream()
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
        return new HashBlocklist(hashes);
    }

    public static void demo() {
        System.out.println("===== Hash Blocklist デモ =====");
        System.out.println();

        HashBlocklist blocklist = new HashBlocklist();
        String maliciousHash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
        blocklist.addHash(maliciousHash);
        blocklist.addHash("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069");
        blocklist.addHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        System.out.println("ブロックリストを構築（既知の悪意あるハッシュ3件を登録）");
        System.out.println("ブロックリスト件数: " + blocklist.size());
        System.out.println();

        // 测试 1: 已知恶意哈希
        System.out.println("テスト1: 既知の悪意あるハッシュを照会");
        System.out.println("  ハッシュ: " + maliciousHash.substring(0, 8) + "...");
        if (blocklist.contains(maliciousHash)) {
            System.out.println("  結果: ⚠️  MALICIOUS - 既知の悪意あるファイル");
        } else {
            System.out.println("  結果: ✓  CLEAN - 既知の脅威は検出されません");
        }
        System.out.println();

        // 测试 2: 未知哈希
        String cleanHash = "0000000000000000000000000000000000000000000000000000000000000000";
        System.out.println("テスト2: 未知のハッシュを照会");
        System.out.println("  ハッシュ: " + cleanHash.substring(0, 10) + "...");
        if (blocklist.contains(cleanHash)) {
            System.out.println("  結果: ⚠️  MALICIOUS - 既知の悪意あるファイル");
        } else {
            System.out.println("  結果: ✓  CLEAN - 既知の脅威は検出されません");
        }
    }

    public static void main(String[] args) {
        demo();
    }
}
