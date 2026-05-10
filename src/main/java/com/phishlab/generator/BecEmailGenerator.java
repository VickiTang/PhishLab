package com.phishlab.generator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * BEC（Business Email Compromise）メールを生成する攻撃者視点のツール。
 */
public class BecEmailGenerator {
    private Random random;
    private long seed;

    private static final Map<String, String> LAST_NAME_ROMAJI = new HashMap<>();
    private static final Map<String, String> ROLE_ROMAJI = new HashMap<>();

    static {
        LAST_NAME_ROMAJI.put("田中", "tanaka");
        LAST_NAME_ROMAJI.put("山田", "yamada");
        LAST_NAME_ROMAJI.put("鈴木", "suzuki");
        LAST_NAME_ROMAJI.put("佐藤", "sato");
        LAST_NAME_ROMAJI.put("高橋", "takahashi");
        LAST_NAME_ROMAJI.put("渡辺", "watanabe");
        LAST_NAME_ROMAJI.put("伊藤", "ito");
        LAST_NAME_ROMAJI.put("中村", "nakamura");
        LAST_NAME_ROMAJI.put("小林", "kobayashi");
        LAST_NAME_ROMAJI.put("加藤", "kato");

        ROLE_ROMAJI.put("社長", "ceo");
        ROLE_ROMAJI.put("副社長", "vp");
        ROLE_ROMAJI.put("代表取締役", "representative");
        ROLE_ROMAJI.put("CEO", "ceo");
        ROLE_ROMAJI.put("CFO", "cfo");
        ROLE_ROMAJI.put("経理部長", "accounting.manager");
        ROLE_ROMAJI.put("営業本部長", "sales.head");
        ROLE_ROMAJI.put("財務担当役員", "finance.exec");
        ROLE_ROMAJI.put("事業開発本部長", "bizdev.head");
        ROLE_ROMAJI.put("海外事業部長", "overseas.mgr");
    }

    public BecEmailGenerator() {
        this(System.currentTimeMillis());
    }

    public BecEmailGenerator(long seed) {
        this.seed = seed;
        this.random = new Random(seed);
    }

    /**
     * テストの再現性のためにシード値を再設定します。
     */
    public void setSeed(long seed) {
        this.seed = seed;
        this.random = new Random(seed);
    }

    /**
     * 1通のBECメールを生成します。
     */
    public BecEmail generate() {
        List<String> usedTactics = new ArrayList<>();
        
        // a) 偽装役職の選択
        String impersonatedRole = getRandomItem(BecTemplates.IMPERSONATED_ROLES);
        usedTactics.add("impersonation");
        
        // b) 日本姓氏・名の選択
        String fromLastName = getRandomItem(BecTemplates.JAPANESE_LAST_NAMES);
        String fromFirstName = getRandomItem(BecTemplates.JAPANESE_FIRST_NAMES);
        String fullPersonName = fromLastName + " " + fromFirstName;
        
        // c) fromName の生成
        String fromName = fromLastName + impersonatedRole;
        
        // d) ドメインの選択
        String fromDomain = getRandomItem(BecTemplates.SUSPICIOUS_FROM_DOMAINS);
        
        // e) フルメールアドレスの生成
        String fullEmail = generateFullEmail(fromLastName, impersonatedRole, fromDomain);
        
        // f) 攻撃手法：緊急性
        String urgency = getRandomItem(BecTemplates.URGENCY_PHRASES);
        usedTactics.add("urgency");
        
        // g) 件名の生成
        String subjectTemplate = getRandomItem(BecTemplates.SUBJECT_TEMPLATES);
        String subject = String.format(subjectTemplate, urgency);
        
        // h) 受信者姓氏の選択（送信者と異なるもの）
        String toLastName;
        do {
            toLastName = getRandomItem(BecTemplates.JAPANESE_LAST_NAMES);
        } while (toLastName.equals(fromLastName));
        
        // i) 尊称の選択
        String honorific = getRandomItem(BecTemplates.RECIPIENT_HONORIFICS);
        String recipient = toLastName + honorific;
        
        // j) 本文の構成
        // [1] 收件人称呼
        // (recipient already generated)

        // [2] 开头
        String openingTemplate = getRandomItem(BecTemplates.BODY_OPENINGS);
        String opening = String.format(openingTemplate, fromLastName);
        
        // [3] 背景情境 (100% 概率)
        String background = getRandomItem(BecTemplates.BACKGROUND_CONTEXTS);
        usedTactics.add("context");

        // [4] 主要要求（金銭手法）
        List<Integer> amounts = Arrays.asList(100, 200, 300, 500, 800, 1000);
        int amount = amounts.get(random.nextInt(amounts.size()));
        String requestTemplate = getRandomItem(BecTemplates.BODY_REQUESTS);
        String request = formatRequest(requestTemplate, urgency, amount);
        usedTactics.add("money");
        
        // [5] 偽の具体的詳細 (各カテゴリ 60% 概率)
        List<String> selectedDetails = new ArrayList<>();
        if (random.nextInt(100) < 60) {
            selectedDetails.add(getRandomItem(BecTemplates.BANK_DETAILS));
        }
        if (random.nextInt(100) < 60) {
            selectedDetails.add(getRandomItem(BecTemplates.INVOICE_DETAILS));
        }
        if (random.nextInt(100) < 60) {
            selectedDetails.add(getRandomItem(BecTemplates.PARTNER_DETAILS));
        }
        
        String details = "";
        if (!selectedDetails.isEmpty()) {
            details = String.join("\n", selectedDetails);
            usedTactics.add("fake_details");
        }

        // [6] 保密要求 (50% 概率)
        String secrecy = "";
        if (random.nextInt(100) < 50) {
            if (random.nextBoolean()) {
                // 方案 A: テンプレート + 短語
                String shortWord = getRandomItem(BecTemplates.SECRECY_SHORT_WORDS);
                String template = getRandomItem(BecTemplates.BODY_SECRECY_TEMPLATES);
                secrecy = String.format(template, shortWord);
            } else {
                // 方案 B: 直接全文
                secrecy = getRandomItem(BecTemplates.SECRECY_FULL_SENTENCES);
            }
            usedTactics.add("secrecy");
        }
        
        // [7] 二次催促 (70% 概率)
        String pressure = "";
        if (random.nextInt(100) < 70) {
            pressure = getRandomItem(BecTemplates.SECONDARY_PRESSURES);
            usedTactics.add("pressure");
        }

        // [8] 结尾
        String closing = getRandomItem(BecTemplates.BODY_CLOSINGS);
        
        // [9] 完整签名 (100% 概率)
        String department = getRandomItem(BecTemplates.DEPARTMENTS);
        int templateIndex = random.nextInt(BecTemplates.FULL_SIGNATURES.size());
        String signatureTemplate = BecTemplates.FULL_SIGNATURES.get(templateIndex);
        String signature;
        
        // テンプレートに応じたパラメータ設定
        if (templateIndex == 0) {
            // [姓 + 名 + 部署 + 役職]
            signature = String.format(signatureTemplate, fromLastName, fromFirstName, department, impersonatedRole);
        } else {
            // [姓 + 名 + 役職 + 部署] (Template 1 and 2)
            signature = String.format(signatureTemplate, fromLastName, fromFirstName, impersonatedRole, department);
        }
        usedTactics.add("signature");

        // 本文の組み立て
        StringBuilder bodyBuilder = new StringBuilder();
        bodyBuilder.append(recipient).append("\n\n");
        bodyBuilder.append(opening).append("\n\n");
        bodyBuilder.append(background).append("\n\n");
        bodyBuilder.append(request);
        if (!details.isEmpty()) {
            bodyBuilder.append("\n\n").append(details);
        }
        if (!secrecy.isEmpty()) {
            bodyBuilder.append("\n\n").append(secrecy);
        }
        if (!pressure.isEmpty()) {
            bodyBuilder.append("\n\n").append(pressure);
        }
        bodyBuilder.append("\n\n").append(closing).append("\n\n");
        bodyBuilder.append(signature);
        
        return new BecEmail(subject, fromName, fromDomain, fullEmail, bodyBuilder.toString(), impersonatedRole, usedTactics);
    }

    /**
     * ローマ字マッピングを使用してリアルなメールアドレスを生成します。
     */
    private String generateFullEmail(String lastName, String role, String domain) {
        String ln = LAST_NAME_ROMAJI.getOrDefault(lastName, "user");
        String r = ROLE_ROMAJI.getOrDefault(role, "staff");
        int num = random.nextInt(90) + 10; // 2位のランダム数字

        int pattern = random.nextInt(4);
        String localPart;
        switch (pattern) {
            case 0: localPart = r + "." + ln; break;
            case 1: localPart = ln + "." + r; break;
            case 2: localPart = r + ln + num; break;
            default: localPart = ln + num; break;
        }
        return localPart + "@" + domain;
    }

    /**
     * 指定された数のBECメールを一括生成します。
     */
    public List<BecEmail> generateBatch(int count) {
        List<BecEmail> batch = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            batch.add(generate());
        }
        return batch;
    }

    private <T> T getRandomItem(List<T> items) {
        return items.get(random.nextInt(items.size()));
    }

    /**
     * テンプレート中 %s と %d 順序を考慮してフォーマットします。
     */
    private String formatRequest(String template, String urgency, int amount) {
        int sPos = template.indexOf("%s");
        int dPos = template.indexOf("%d");
        if (sPos < dPos) {
            return String.format(template, urgency, amount);
        } else {
            return String.format(template, amount, urgency);
        }
    }

    public static void main(String[] args) {
        System.out.println("===== BEC Email Generator デモ =====");
        System.out.println();
        System.out.println("攻撃者になりきって、3 通の偽 BEC メールを生成します。");
        System.out.println("全データは合成データであり、研究目的のみです。");
        System.out.println();

        BecEmailGenerator generator = new BecEmailGenerator();
        List<BecEmail> emails = generator.generateBatch(3);

        for (int i = 0; i < emails.size(); i++) {
            System.out.printf("┌──────────────── Email %d ────────────────┐%n", i + 1);
            System.out.println(emails.get(i).toFormattedString());
            System.out.println("└────────────────────────────────────────┘");
            System.out.println();
        }

        System.out.println("✅ 3 通の BEC メールを生成完了。");
    }
}
