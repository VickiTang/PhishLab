package com.phishlab.generator;

import java.util.*;

public class UrlPhishingEmailGenerator {

    private final Random random;
    private final PhishingDomainGenerator phishingDomainGenerator;

    // 添加 type 字段 (financial/tech/logistics)
    private record BrandInfo(String displayName, String legitDomain, String type, List<Scenario> scenarios) {}
    private record Scenario(String title, String bodyTemplate) {}

    private static final Map<String, BrandInfo> BRAND_TARGETS;
    private static final String[] ATTACK_STRATEGIES = {"TYPO", "COMBO", "TLD_ABUSE"};
    private static final String[] SUSPICIOUS_TLDS = {".tk", ".ml", ".top", ".xyz", ".click", ".work", ".loan"};
    private static final String[] COMBO_KEYWORDS = {"security", "account", "verify", "auth", "support", "service", "login", "secure", "info"};
    private static final String[] URL_PATHS = {"/login", "/verify", "/auth/secure", "/account/confirm", "/cancel"};
    private static final String[] FROM_PREFIXES = {"support", "no-reply"};

    // --- 新增公共段落库 ---
    private static final String[] SALUTATIONS = {"お客様", "お客様各位", "ご利用者様"};
    
    private static final Map<String, String> GREETINGS_BY_BRAND_TYPE = Map.of(
        "financial", "平素より格別のご愛顧を賜り、誠にありがとうございます。",
        "tech", "いつも当社サービスをご利用いただき、ありがとうございます。",
        "logistics", "いつも当社をご利用いただき、ありがとうございます。"
    );

    private static final String[] CALL_TO_ACTION_TEMPLATES = {
        "詳細については、以下のURLからご確認いただけます：\n%URL%",
        "以下のリンクより、お手続きを完了させてください：\n%URL%",
        "内容の確認および修正は、こちらから行ってください：\n%URL%",
        "下記URLより詳細をご確認ください：\n%URL%"
    };

    private static final String[] URGENCY_REMINDERS = {
        "24時間以内に必ずご確認をお願いいたします。",
        "本日中のご対応をお願いいたします。",
        "至急ご対応ください。",
        "速やかにご確認ください。"
    };

    private static final String[] APOLOGIES = {
        "ご不便をおかけし申し訳ございません。",
        "お手数をおかけいたしますが、何卒よろしくお願いいたします。",
        "ご協力のほど、よろしくお願い申し上げます。"
    };

    private static final String[] SIGNATURES_TEMPLATE = {
        "%s サポートチーム",
        "%s カスタマーサポート\n──────────────\n本メールは送信専用アドレスから配信されています",
        "%s セキュリティセンター\nお問い合わせ: support@%s"
    };

    static {
        Map<String, BrandInfo> brands = new LinkedHashMap<>();

        // 更新 BrandInfo，加入类型字段，并精简核心场景文本
        brands.put("amazon", new BrandInfo(
            "Amazon カスタマーサービス",
            "amazon.co.jp",
            "tech",
            List.of(
                new Scenario(
                    "【重要】アカウントが一時停止されました",
                    "お客様のアカウントに不審なログインが検出されました。セキュリティ保護のため、アカウントを一時制限させていただいております。"
                ),
                new Scenario(
                    "【ご注文の確認】身に覚えのないご注文",
                    "お客様のアカウントから ¥48,000 の注文（商品番号：AMZ-9921-X）を承りました。"
                )
            )
        ));

        brands.put("paypal", new BrandInfo(
            "PayPal セキュリティ",
            "paypal.com",
            "financial",
            List.of(
                new Scenario(
                    "【緊急】不審な取引が検出されました",
                    "本日 02:34 に米国からの不審なログインが确认されました。第三者による不正操作の疑いがあります。"
                )
            )
        ));

        brands.put("smbc", new BrandInfo(
            "三井住友銀行",
            "smbc.co.jp",
            "financial",
            List.of(
                new Scenario(
                    "【重要】ワンタイムパスワード再設定のお願い",
                    "セキュリティシステムの更新に伴い、ワンタイムパスワードの再設定が必要となりました。"
                ),
                new Scenario(
                    "【SMBC】お取引内容のご確認",
                    "最新のお取引状況に基づき、登録情報の确认をお願いしております。"
                )
            )
        ));

        brands.put("yamato", new BrandInfo(
            "ヤマト運輸",
            "kuronekoyamato.co.jp",
            "logistics",
            List.of(
                new Scenario(
                    "【不在通知】お荷物のお届けについて",
                    "お荷物のお届けに伺いましたが、宛先不明またはご不在のため持ち帰りました。"
                )
            )
        ));

        brands.put("jcb", new BrandInfo(
            "JCBカード",
            "jcb.co.jp",
            "financial",
            List.of(
                new Scenario(
                    "【重要】カード利用确认のお願い",
                    "お客様のカードで通常と異なるご利用パターンが検出されました。カードの利用状況を緊急で确认する必要があります。"
                )
            )
        ));

        brands.put("microsoft", new BrandInfo(
            "Microsoft アカウント",
            "microsoft.com",
            "tech",
            List.of(
                new Scenario(
                    "【警告】異常なサインイン試行を検出",
                    "Microsoft アカウントへの不審なアクセス試行をブロックしました。アカウントを保護するために情報の确认をお願いします。"
                )
            )
        ));

        brands.put("mercari", new BrandInfo(
            "メルカリ事務局",
            "mercari.com",
            "tech",
            List.of(
                new Scenario(
                    "【要対応】出品商品の情報确认のお願い",
                    "現在出品されている商品に関し、ガイドライン遵守の観点から本人确认情報の再登録をお願いしております。"
                )
            )
        ));

        BRAND_TARGETS = Collections.unmodifiableMap(brands);
    }

    public UrlPhishingEmailGenerator() {
        this.random = new Random();
        this.phishingDomainGenerator = new PhishingDomainGenerator();
    }

    public UrlPhishingEmailGenerator(long seed) {
        this.random = new Random(seed);
        this.phishingDomainGenerator = new PhishingDomainGenerator();
        this.phishingDomainGenerator.setSeed(seed);
    }

    /**
     * 修改后的生成逻辑，按 7 段式组装邮件
     */
    public BecEmail generate() {
        List<String> brandKeys = new ArrayList<>(BRAND_TARGETS.keySet());
        String brandKey = brandKeys.get(random.nextInt(brandKeys.size()));
        return generateForBrand(brandKey);
    }

    /**
     * 针对特定品牌生成邮件，方便批量生成时控制不重复
     */
    private BecEmail generateForBrand(String brandKey) {
        BrandInfo brand = BRAND_TARGETS.get(brandKey);
        
        // 1. 生成钓鱼域名和URL
        String strategy = ATTACK_STRATEGIES[random.nextInt(ATTACK_STRATEGIES.length)];
        String phishingDomain = generatePhishingDomain(brandKey, brand.legitDomain(), strategy);
        String path = URL_PATHS[random.nextInt(URL_PATHS.length)];
        String url = "https://" + phishingDomain + path;

        // 2. 选择场景
        Scenario scenario = brand.scenarios().get(random.nextInt(brand.scenarios().size()));

        // 3. 按 7 段结构组装正文
        String salutation = SALUTATIONS[random.nextInt(SALUTATIONS.length)];
        String greeting = GREETINGS_BY_BRAND_TYPE.getOrDefault(brand.type(), "いつも当社サービスをご利用いただき、ありがとうございます。");
        String coreMessage = scenario.bodyTemplate();
        String cta = CALL_TO_ACTION_TEMPLATES[random.nextInt(CALL_TO_ACTION_TEMPLATES.length)].replace("%URL%", url);
        String urgency = URGENCY_REMINDERS[random.nextInt(URGENCY_REMINDERS.length)];
        String apology = APOLOGIES[random.nextInt(APOLOGIES.length)];
        
        String sigTemplate = SIGNATURES_TEMPLATE[random.nextInt(SIGNATURES_TEMPLATE.length)];
        String signature;
        if (sigTemplate.contains("support@%s")) {
            signature = String.format(sigTemplate, brand.displayName(), phishingDomain);
        } else {
            signature = String.format(sigTemplate, brand.displayName());
        }

        String fullBody = String.join("\n\n", 
            salutation,
            greeting,
            coreMessage,
            cta,
            urgency,
            apology,
            signature
        );

        String fromPrefix = FROM_PREFIXES[random.nextInt(FROM_PREFIXES.length)];
        String fromAddress = fromPrefix + "@" + phishingDomain;

        return new BecEmail(
            scenario.title(),
            brand.displayName(),
            phishingDomain,
            fromAddress,
            fullBody,
            "",
            List.of("url_phishing", strategy)
        );
    }

    /**
     * 修改后的批量生成逻辑，确保品牌不重复
     */
    public List<BecEmail> generateBatch(int count) {
        List<String> brandKeys = new ArrayList<>(BRAND_TARGETS.keySet());
        Collections.shuffle(brandKeys, random);
        
        List<BecEmail> result = new ArrayList<>();
        int actualCount = Math.min(count, brandKeys.size());
        
        for (int i = 0; i < actualCount; i++) {
            result.add(generateForBrand(brandKeys.get(i)));
        }
        
        return result;
    }

    private String generatePhishingDomain(String brandKey, String legitDomain, String strategy) {
        return switch (strategy) {
            case "TYPO" -> {
                List<String> variants = phishingDomainGenerator.typoSquat(legitDomain);
                yield variants.stream()
                    .filter(v -> !v.contains("@"))
                    .findFirst()
                    .orElse(brandKey + "-secure.com");
            }
            case "COMBO" -> {
                String keyword = COMBO_KEYWORDS[random.nextInt(COMBO_KEYWORDS.length)];
                String tld = random.nextBoolean() ? ".com" : ".net";
                yield brandKey + "-" + keyword + tld;
            }
            case "TLD_ABUSE" -> {
                String suffix = COMBO_KEYWORDS[random.nextInt(COMBO_KEYWORDS.length)];
                String tld = SUSPICIOUS_TLDS[random.nextInt(SUSPICIOUS_TLDS.length)];
                yield brandKey + "-" + suffix + tld;
            }
            default -> brandKey + ".tk";
        };
    }

    public static void main(String[] args) {
        System.out.println("===== URL Phishing Email Generator デモ =====");
        System.out.println();
        System.out.println("攻撃者になりきって、3 通の異なるブランド、高密度な URL フィッシングメールを生成します。");
        System.out.println();

        UrlPhishingEmailGenerator generator = new UrlPhishingEmailGenerator();
        List<BecEmail> emails = generator.generateBatch(3);

        for (int i = 0; i < emails.size(); i++) {
            BecEmail email = emails.get(i);
            System.out.println("┌──────────────── Email " + (i + 1) + " (Brand: " + email.fromName() + ") ────────────────┐");
            System.out.println(email.toFormattedString());
            System.out.println("└────────────────────────────────────────────────────────────────────────────┘");
            System.out.println();
        }
    }
}
