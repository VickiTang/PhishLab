# 🎣 PhishLab
**「メール内容を読み取らずに」フィッシングの脅威を特定する研究用プロトタイプ**

---

## ⚠️ 重要声明
本プロジェクトで使用されているデータ（ドメイン名、メールアドレス、ブランド名等）は、**すべて研究用に生成された合成データ（Synthetic Data）**です。
*   実在する企業、組織、個人とは一切関係ありません。
*   プライバシー保護の観点から、メール本文の内容（Content）には一切触れず、メタデータとドメイン構造のみで検知を試みるアプローチを採用しています。

---

## 📸 スクリーンショット
![Web UI Simulator Placeholder](https://via.placeholder.com/800x450.png?text=PhishLab+Inbox+Simulator+UI)
*（シミュレートされた受信トレイで、メールをクリックするとリアルタイムで5つの検出器がリスクを判定します）*

---

## 🚀 クイックスタート

以下の3ステップで、ローカル環境でシミュレーターを起動できます。

```bash
# プロジェクトのビルド
mvn clean package

# アプリケーションの実行
java -jar target/phishlab-0.1-SNAPSHOT.jar

# ブラウザでアクセス
# http://localhost:8080
```

---

## ✨ プロジェクトの特徴

-   **プライバシー重視の設計**: 本文を解析せず、URL構造、ドメイン特性、ハッシュ値のみで判定。
-   **攻防一体のフレームワーク**: BEC（ビジネスメール詐欺）とURLフィッシングの攻撃Generatorを内蔵。
-   **リアルタイム・シミュレーション**: Web UIを通じて、攻撃と防御のやり取りを視覚的に体験。
-   **多層防御アルゴリズム**: 単一のロジックではなく、5つの異なる戦略を融合させた検知エンジン。

---

## 🔍 検出器一覧 (Detectors)

| 検出器 | 検知対象の攻撃 | ロジックの概要 |
| :--- | :--- | :--- |
| **Levenshtein Detector** | Typo Squatting | `amazon` → `amazom` のような編集距離の近い類似ドメインを特定。 |
| **Brand Keyword Matcher** | Combo Squatting | `amazon-security.com` のようにブランド名を含む攻撃用ドメインを検知。 |
| **Suspicious TLD Checker** | TLD Abuse | `.tk`, `.cf`, `.ga` など、フィッシングに悪用されやすいTLDをブロック。 |
| **Homoglyph & Letter Swap** | Visual Deception | `jcb` → `jbc` (交換) や `amazon` → `amaz0n` (同形字) を検知。 |
| **Hash Blocklist Service** | Known Threats | SHA-256を用いたブラックリスト照合により、既知の脅威を100%召喚。 |

---

## 🧪 研究プロセス：100% → 50% → 90% の物語

本プロジェクトは、単なるツールの開発ではなく、検知精度の限界に挑んだ研究の記録です。

1.  **Phase 1: 偽りの繁栄 (Detection 100%)**
    単純なキーワード一致のみを実装した段階。用意した単純な攻撃サンプルをすべて検知できたが、現実の複雑な攻撃には無力であることが判明。
2.  **Phase 2: 現実の壁 (Detection 50%)**
    多様なドメイン変異（Typo/Combo/TLD）を含む「リアルな攻撃セット」を導入した途端、検知率が半分に急落。攻撃手法の多様性を過小評価していたことが露呈。
3.  **Phase 3: 戦略の融合 (Detection 90%)**
    複数の検出器を統合（Strategy Fusion）し、Homoglyph検知やハッシュベースの脅威インテリジェンスを追加。偽陽性を抑えつつ、未知・既知両方の攻撃に対して高いカバー率を達成。

---

## 🏗 アーキテクチャ図

```text
[ Web UI (JS/HTML) ] <----> [ REST API (Java HttpServer) ]
                                     |
                                     v
[ Battle Runner (Evaluation) ] <--- [ Detection Engine ]
             |                       /      |      \
             v                      /       |       \
[ Attack Generators ] --------> [Detector] [Detector] [HashList]
   (BEC / URL Phish)
```

---

## 🛠 技術スタック

-   **Backend**: Java 21 (LTS)
-   **Build Tool**: Maven 3.9+
-   **Frontend**: Vanilla JS / CSS / HTML5 (外部フレームワーク未使用)
-   **Communication**: Native Java HttpServer (No Spring/Jackson)
-   **Security**: SHA-256 Hashing / Levenshtein Distance Algorithm

---

## 📂 ファイル構成

```text
phishlab/
├── pom.xml                 # Maven構成
├── src/main/java/com/phishlab/
│   ├── PhishLabApp.java    # メインエントリ（Webサーバ起動）
│   ├── InteractiveDemo.java# CLIデモ用
│   ├── detector/           # 検知ロジック（Levenshtein, TLD, etc.）
│   ├── generator/          # 攻撃データ生成器（BEC, URL Phish）
│   ├── hash/               # ハッシュ関連ツールとブラックリスト管理
│   ├── battle/             # 攻防評価フレームワーク
│   └── web/                # HTTPハンドラとJSONユーティリティ
└── src/main/resources/
    ├── index.html          # シミュレータフロントエンド
    └── data/               # 合成データセット（JSON/TXT）
```

---

## ⚠️ 既知の制約と今後の課題 (Future Work)

-   **ブラックリストの規模**: 現在のハッシュリストは研究用のスモールセットです。実用化には大規模な脅威インテリジェンス（Feed）との連携が必要です。
-   **同形字（Homoglyph）攻撃**: 基本的な文字置換には対応していますが、Unicodeの特殊文字を駆使した高度な視覚的欺瞞にはまだ改善の余地があります。
-   **コンテキスト解析**: 本文を読み取らない制約上、文脈（Context）に依存する高度なBEC攻撃の検知には限界があります。
