package com.phishlab.detector;

public enum RiskLevel {
    GREEN("✓", "\u001B[32m", "低リスク"),
    YELLOW("⚠", "\u001B[33m", "中リスク"),
    RED("⛔", "\u001B[31m", "高リスク");

    private final String icon;
    private final String ansiColor;
    private final String label;

    RiskLevel(String icon, String ansiColor, String label) {
        this.icon = icon;
        this.ansiColor = ansiColor;
        this.label = label;
    }

    public String getIcon() { return icon; }
    public String getAnsiColor() { return ansiColor; }
    public String getLabel() { return label; }
    
    public static String reset() {
        return "\u001B[0m";
    }
}
