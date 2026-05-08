package com.phishlab.detector;

import java.util.List;

public record DetectionResult(String target, RiskLevel riskLevel, int score, List<String> reasons) {
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(riskLevel.getAnsiColor())
          .append(riskLevel.getIcon())
          .append(" ")
          .append(riskLevel.name())
          .append(" ")
          .append(riskLevel.getLabel().toUpperCase())
          .append(": ")
          .append(target)
          .append(RiskLevel.reset())
          .append("\n");
        
        sb.append("   Score: ").append(score).append("/100\n");
        sb.append("   判定理由:\n");
        for (String reason : reasons) {
            sb.append("     - ").append(reason).append("\n");
        }
        return sb.toString();
    }
}
