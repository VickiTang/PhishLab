package com.phishlab.generator;

import java.util.List;
import java.util.Arrays;

/**
 * BECメールの素材ライブラリ。
 * 日本のビジネス環境で一般的に見られる攻撃表現を提供します。
 */
public class BecTemplates {

    // 緊急性表現
    public static final List<String> URGENCY_PHRASES = Arrays.asList(
        "至急",
        "緊急",
        "本日中",
        "ASAP",
        "急ぎ",
        "今すぐ",
        "至急対応願います",
        "本件は急を要します"
    );

    // 金銭関連表現
    public static final List<String> MONEY_PHRASES = Arrays.asList(
        "振込",
        "送金",
        "請求書",
        "支払い",
        "口座変更",
        "新しい口座",
        "振込先変更"
    );

    // 短い機密ワード（モダレートで挿入用）
    public static final List<String> SECRECY_SHORT_WORDS = Arrays.asList(
        "内密",
        "他言無用",
        "秘密",
        "極秘",
        "秘匿",
        "口外厳禁"
    );

    // 完成した機密文（直接1行として使用）
    public static final List<String> SECRECY_FULL_SENTENCES = Arrays.asList(
        "本件は秘匿性が高いため、他の方には共有しないでください。",
        "重要案件のため、本メールは関係者以外に転送しないでください。",
        "守秘事項のため、内密にお願いいたします。",
        "本件は他言無用にてお願いいたします。",
        "情報漏洩防止のため、本件は当事者間のみで進めてください。"
    );

    // 偽装役職
    public static final List<String> IMPERSONATED_ROLES = Arrays.asList(
        "社長",
        "副社長",
        "代表取締役",
        "CFO",
        "CEO",
        "経理部長",
        "営業本部長",
        "財務担当役員",
        "事業開発本部長",
        "海外事業部長"
    );

    // 日本人の姓
    public static final List<String> JAPANESE_LAST_NAMES = Arrays.asList(
        "田中", "山田", "鈴木", "佐藤", "高橋",
        "渡辺", "伊藤", "中村", "小林", "加藤"
    );

    // 日本人の名
    public static final List<String> JAPANESE_FIRST_NAMES = Arrays.asList(
        "太郎", "健一", "達也", "雄一", "宏", "俊夫",
        "誠", "和也", "智彦", "拓海", "翔太"
    );

    // 受信者の敬称
    public static final List<String> RECIPIENT_HONORIFICS = Arrays.asList(
        "さん", "様"
    );

    // 怪しい送信ドメイン
    public static final List<String> SUSPICIOUS_FROM_DOMAINS = Arrays.asList(
        "gmail.com",
        "yahoo.co.jp",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com"
    );

    // 件名テンプレート
    public static final List<String> SUBJECT_TEMPLATES = Arrays.asList(
        "【%s】本日中の振込対応について",
        "【%s】口座変更のお願い",
        "【%s】請求書のご対応",
        "【%s】秘密案件のご相談",
        "【%s】支払い処理のご依頼"
    );

    // 本文：冒頭
    public static final List<String> BODY_OPENINGS = Arrays.asList(
        "お疲れ様です。%sです。",
        "いつもお世話になっております。%sです。",
        "%sです。お忙しいところ恐縮です。"
    );

    // 本文：要求（%s: 緊急表現, %d: 金額）
    public static final List<String> BODY_REQUESTS = Arrays.asList(
        "%s、以下の口座に%d万円を振込んでいただきたく、お願いいたします。",
        "%s対応していただきたい案件があります。%d万円の支払いをお願いします。",
        "新しい取引先からの請求書につき、%d万円の振込を%sお願いします。"
    );

    // 本文：機密保持テンプレート（短語挿入用）
    public static final List<String> BODY_SECRECY_TEMPLATES = Arrays.asList(
        "本件は%s扱いのため、他の方には共有しないでください。",
        "%s事項のため、社内でも限られたメンバーのみで対応願います。",
        "%sのため、メール内容を外部に転送しないでください。"
    );

    // 本文：結び
    public static final List<String> BODY_CLOSINGS = Arrays.asList(
        "詳細は別途ご連絡します。",
        "ご対応のほど、よろしくお願いいたします。",
        "確認次第、すぐにご返信ください。"
    );

    // 背景情境
    public static final List<String> BACKGROUND_CONTEXTS = Arrays.asList(
        "取引先からの督促を受けており、対応が必要です。",
        "明日の役員会で議題になっており、本日中に処理する必要があります。",
        "監査対応の関係で、本日中に完了させる必要があります。",
        "新規プロジェクトの契約締結に関わる件です。",
        "海外支社からの依頼で、時差の関係で急ぎとなっております。",
        "親会社からの指示があり、対応が遅れると問題になります。"
    );

    // 偽の具体的詳細: 銀行
    public static final List<String> BANK_DETAILS = Arrays.asList(
        "振込先: みずほ銀行 渋谷支店 普通 1234567",
        "振込先: 三井住友銀行 新宿支店 普通 7654321",
        "振込先: 三菱UFJ銀行 丸の内支店 普通 9876543",
        "振込先: りそな銀行 大手町支店 普通 2468135"
    );

    // 偽の具体的詳細: 請求書
    public static final List<String> INVOICE_DETAILS = Arrays.asList(
        "請求書番号: INV-2026-0837",
        "案件番号: PJ-2026-1124",
        "発注番号: PO-2026-9921"
    );

    // 偽の具体的詳細: 取引先
    public static final List<String> PARTNER_DETAILS = Arrays.asList(
        "取引先: 株式会社グローバルテック",
        "取引先: 山田商事株式会社",
        "取引先: 三和コンサルティング"
    );

    // 二次催促
    public static final List<String> SECONDARY_PRESSURES = Arrays.asList(
        "念のため再度お願いします、本日中の対応を厳守してください。",
        "必ず本日17時までにご対応ください。",
        "緊急案件のため、他の業務より優先してください。",
        "対応完了次第、すぐに私にご連絡ください。",
        "もし対応が遅れる場合は、すぐに直接ご連絡ください。"
    );

    // 署名テンプレート
    public static final List<String> FULL_SIGNATURES = Arrays.asList(
        "%s %s\n%s %s\n株式会社グローバルテック\nTEL: 03-XXXX-XXXX",
        "%s %s\n%s\n%s\n株式会社グローバルテック",
        "──────────────\n%s %s（%s）\n%s\n株式会社グローバルテック\nMobile: 090-XXXX-XXXX"
    );

    // 部署名
    public static final List<String> DEPARTMENTS = Arrays.asList(
        "経営企画部",
        "経理部",
        "営業本部",
        "事業開発部",
        "海外事業部",
        "プロジェクト推進室"
    );

    public static void main(String[] args) {
        System.out.println("===== BEC Templates 素材ライブラリ =====");
        System.out.println();

        printCategory("📋 緊急性表現 (URGENCY)", URGENCY_PHRASES);
        printCategory("💰 金銭関連表現 (MONEY)", MONEY_PHRASES);
        printCategory("🤫 機密短文 (SECRECY_SHORT_WORDS)", SECRECY_SHORT_WORDS);
        printCategory("🤫 機密全文 (SECRECY_FULL_SENTENCES)", SECRECY_FULL_SENTENCES);
        printCategory("👔 偽装役職 (ROLES)", IMPERSONATED_ROLES);
        printCategory("📧 怪しい送信ドメイン", SUSPICIOUS_FROM_DOMAINS);
        printCategory("📑 件名テンプレート", SUBJECT_TEMPLATES);
        printCategory("背景情境 (BACKGROUND_CONTEXTS)", BACKGROUND_CONTEXTS);
        printCategory("二次催促 (SECONDARY_PRESSURES)", SECONDARY_PRESSURES);
        printCategory("署名テンプレート (FULL_SIGNATURES)", FULL_SIGNATURES);
        printCategory("部署名 (DEPARTMENTS)", DEPARTMENTS);

        int totalCount = URGENCY_PHRASES.size() + MONEY_PHRASES.size() + 
                         SECRECY_SHORT_WORDS.size() + SECRECY_FULL_SENTENCES.size() +
                         IMPERSONATED_ROLES.size() + JAPANESE_LAST_NAMES.size() + 
                         JAPANESE_FIRST_NAMES.size() +
                         RECIPIENT_HONORIFICS.size() + SUSPICIOUS_FROM_DOMAINS.size() + 
                         SUBJECT_TEMPLATES.size() + BODY_OPENINGS.size() + 
                         BODY_REQUESTS.size() + BODY_SECRECY_TEMPLATES.size() + BODY_CLOSINGS.size() +
                         BACKGROUND_CONTEXTS.size() + BANK_DETAILS.size() + 
                         INVOICE_DETAILS.size() + PARTNER_DETAILS.size() +
                         SECONDARY_PRESSURES.size() +
                         FULL_SIGNATURES.size() + DEPARTMENTS.size();

        System.out.println("----------------------------------------");
        System.out.println("合計: " + totalCount + " 件の攻撃素材");
    }

    private static void printCategory(String title, List<String> items) {
        System.out.printf("%s: %d 件%n", title, items.size());
        System.out.println("  - " + String.join(", ", items));
        System.out.println();
    }
}
