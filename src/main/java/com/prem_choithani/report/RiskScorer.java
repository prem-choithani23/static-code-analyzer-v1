package com.prem_choithani.report;

import com.prem_choithani.model.Vulnerability;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RiskScorer {

    private static final Map<String, Integer> RISK_MAP = new HashMap<>();

    static {

        RISK_MAP.put("SQL Injection", 100);
        RISK_MAP.put("XSS", 80);
        RISK_MAP.put("Template Injection", 85);
        RISK_MAP.put("Security Misconfiguration", 50);

    }

    public void assignRiskScores(List<Vulnerability> vulnerabilities) {

        for (Vulnerability v : vulnerabilities) {

            int score = RISK_MAP.getOrDefault(v.getType(), 30);

            System.out.println(
                    v.getType() + " risk score: " + score
            );

        }
    }
}