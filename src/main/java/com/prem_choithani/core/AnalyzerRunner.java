package com.prem_choithani.core;


import com.prem_choithani.model.Vulnerability;
import com.prem_choithani.report.JSONReportGenerator;
import com.prem_choithani.report.HTMLReportGenerator;
import com.prem_choithani.report.RiskScorer;

import java.util.List;


public class AnalyzerRunner {

    public void run(String projectPath) {

        AnalyzerEngine engine = new AnalyzerEngine();

        System.out.println("Starting security analysis...");

        List<Vulnerability> vulnerabilities =
                engine.analyzeProject(projectPath);

        System.out.println("Total vulnerabilities detected: "
                + vulnerabilities.size());

        RiskScorer scorer = new RiskScorer();

        scorer.assignRiskScores(vulnerabilities);

        JSONReportGenerator json = new JSONReportGenerator();
        json.generate(vulnerabilities);

        HTMLReportGenerator html = new HTMLReportGenerator();
        html.generate(vulnerabilities);

        System.out.println("Analysis completed.");

    }

}