package com.prem_choithani.report;

import com.prem_choithani.model.Vulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Generates a JSON security report from a list of detected vulnerabilities.
 *
 * FIXES APPLIED
 * -------------
 * 1. HARDCODED OUTPUT PATH: "security-report.json" was baked in.
 *    Fixed with a configurable outputPath field (constructor injection).
 *    The no-arg constructor defaults to the original name for backward
 *    compatibility.
 *
 * 2. REPLACED System.out.println / e.printStackTrace() with Logger.
 *
 * 3. ADDED ObjectMapper configuration: FAIL_ON_EMPTY_BEANS = false so
 *    that model objects without Jackson annotations do not cause
 *    serialization errors.
 */
public class JSONReportGenerator {

    private static final Logger LOGGER = Logger.getLogger(JSONReportGenerator.class.getName());

    private static final String DEFAULT_OUTPUT_PATH = "security-report.json";

    private final String outputPath;

    public JSONReportGenerator() {
        this(DEFAULT_OUTPUT_PATH);
    }

    public JSONReportGenerator(String outputPath) {
        this.outputPath = outputPath;
    }

    public void generate(List<Vulnerability> vulnerabilities) {

        try {
            ObjectMapper mapper = new ObjectMapper();
            // FIX 3: prevents serialization failure on POJOs without annotations
            mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

            ObjectNode root = mapper.createObjectNode();

            ObjectNode summary = mapper.createObjectNode();
            summary.put("total_vulnerabilities", vulnerabilities.size());

            // Count by severity
            long critical = vulnerabilities.stream().filter(v -> "CRITICAL".equals(v.getSeverity())).count();
            long high     = vulnerabilities.stream().filter(v -> "HIGH".equals(v.getSeverity())).count();
            long medium   = vulnerabilities.stream().filter(v -> "MEDIUM".equals(v.getSeverity())).count();
            long low      = vulnerabilities.stream().filter(v -> "LOW".equals(v.getSeverity())).count();

            summary.put("critical", critical);
            summary.put("high",     high);
            summary.put("medium",   medium);
            summary.put("low",      low);

            root.set("scan_summary", summary);
            root.putPOJO("vulnerabilities", vulnerabilities);

            mapper.writerWithDefaultPrettyPrinter()
                    .writeValue(new File(outputPath), root);

            // FIX 2: proper logger
            LOGGER.info("JSON report generated: " + outputPath);

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "JSON report generation failed for path: " + outputPath, e);
        }
    }
}