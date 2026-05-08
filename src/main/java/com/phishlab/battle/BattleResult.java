package com.phishlab.battle;

import java.util.List;

public record BattleResult(
    String target,
    int totalAttacks,
    int detectedCount,
    int missedCount,
    List<String> missedVariants,
    List<String> detectedVariants
) {
    public double detectionRate() {
        if (totalAttacks == 0) return 0.0;
        return (double) detectedCount / totalAttacks * 100.0;
    }
}
