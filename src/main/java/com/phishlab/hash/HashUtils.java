package com.phishlab.hash;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class HashUtils {

    public static String sha256(String input) {
        return sha256(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    public static String sha256OfFile(Path filePath) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream is = Files.newInputStream(filePath);
                 DigestInputStream dis = new DigestInputStream(is, digest)) {
                byte[] buffer = new byte[8192];
                while (dis.read(buffer) != -1) ;
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    public static void demo() {
        String input1 = "Hello World";
        String input2 = "Hello World!";

        String hash1 = sha256(input1);
        String hash2 = sha256(input2);

        int differences = 0;
        for (int i = 0; i < hash1.length(); i++) {
            if (hash1.charAt(i) != hash2.charAt(i)) {
                differences++;
            }
        }

        System.out.println("===== SHA-256 アバランチ効果デモ =====");
        System.out.println();
        System.out.println("入力1: \"" + input1 + "\"");
        System.out.println("SHA-256: " + hash1);
        System.out.println();
        System.out.println("入力2: \"" + input2 + "\"  （1文字追加のみ）");
        System.out.println("SHA-256: " + hash2);
        System.out.println();
        System.out.println("差分分析: 64桁中" + differences + "桁が完全に異なる");
        System.out.println("アバランチ効果: 入力が1文字変わるだけで、出力の" + (int)((differences / 64.0) * 100) + "%が変化");
    }

    public static void main(String[] args) {
        demo();
    }
}
