package com.phishlab.generator;

import java.util.List;

/**
 * BEC（Business Email Compromise）メールを表す不変データクラス。
 */
public record BecEmail(
    String subject,              // 件名
    String fromName,             // 送信者の表示名（例：田中部長）
    String fromDomain,           // 送信元ドメイン（例：gmail.com）
    String fullEmail,            // 送信元のフルメールアドレス（例：ceo.tanaka@gmail.com）
    String body,                 // 本文
    String impersonatedRole,     // 偽装した役職（社長/部長/CFO 等）
    List<String> usedTactics    // 使用した攻撃手口（urgency/secrecy/money 等）
) {
    /**
     * 実際のメールに近い形式でフォーマットされた文字列を返します。
     */
    public String toFormattedString() {
        String emailToDisplay = (fullEmail != null) ? fullEmail : fromDomain;
        return String.format(
            "差出人: %s <%s>%n" +
            "件名: %s%n" +
            "─────────────────────────────────%n" +
            "%s%n" +
            "─────────────────────────────────%n" +
            "[偽装役職: %s | 攻撃手法: %s]",
            fromName, 
            emailToDisplay,
            subject,
            body,
            impersonatedRole,
            String.join(", ", usedTactics)
        );
    }
}
