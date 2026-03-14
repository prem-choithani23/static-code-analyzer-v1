package com.prem_choithani.report;

import com.prem_choithani.model.Vulnerability;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Generates an HTML security report from a list of detected vulnerabilities.
 *
 * FIXES APPLIED
 * -------------
 * 1. RESOURCE LEAK: The original code used a bare FileWriter and called
 *    writer.close() manually.  If any write throws, the file was never
 *    closed.  Fixed with try-with-resources on PrintWriter(FileWriter).
 *
 * 2. XSS IN REPORT (ironic): The original code wrote vulnerability data
 *    directly into HTML:
 *
 *       writer.write("<td>" + v.getDescription() + "</td>");
 *
 *    If a vulnerability description or file name contained < > & " '
 *    the HTML report itself would be malformed or executable.
 *    Fixed with escapeHtml() applied to every dynamic value.
 *
 * 3. HARDCODED OUTPUT PATH: "security-report.html" was baked in.
 *    Fixed with a configurable outputPath field set via constructor.
 *    The no-arg constructor defaults to the original filename for
 *    backward compatibility.
 *
 * 4. CHARACTER ENCODING: FileWriter without charset defaults to the
 *    platform default (varies by OS/JVM).  Fixed with explicit UTF-8.
 *
 * 5. REPLACED System.out.println / e.printStackTrace() with Logger.
 */
public class HTMLReportGenerator {

    private static final Logger LOGGER = Logger.getLogger(HTMLReportGenerator.class.getName());

    private static final String DEFAULT_OUTPUT_PATH = "security-report.html";

    private final String outputPath;

    /** Writes report to the default path (backward-compatible). */
    public HTMLReportGenerator() {
        this(DEFAULT_OUTPUT_PATH);
    }

    /** Writes report to a configurable path. */
    public HTMLReportGenerator(String outputPath) {
        this.outputPath = outputPath;
    }

    public void generate(List<Vulnerability> vulnerabilities) {

        // FIX 1 & 4: try-with-resources + explicit UTF-8 charset
        try (PrintWriter writer = new PrintWriter(
                new FileWriter(outputPath, StandardCharsets.UTF_8))) {

            writeHtml(writer, vulnerabilities);
            LOGGER.info("HTML report generated: " + outputPath);

        } catch (IOException e) {
            // FIX 5: proper logger instead of System.out + printStackTrace
            LOGGER.log(Level.SEVERE, "HTML report generation failed for path: " + outputPath, e);
        }
    }

    private void writeHtml(PrintWriter w, List<Vulnerability> vulns) {

        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        w.println("<!DOCTYPE html>");
        w.println("<html lang=\"en\">");
        w.println("<head>");
        w.println("  <meta charset=\"UTF-8\">");
        w.println("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        w.println("  <title>Security Analysis Report</title>");
        w.println("  <style>");
        w.println("    body { font-family: Arial, sans-serif; margin: 24px; color: #222; }");
        w.println("    h1   { color: #b22222; }");
        w.println("    table{ border-collapse: collapse; width: 100%; margin-top: 16px; }");
        w.println("    th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }");
        w.println("    th   { background-color: #333; color: #fff; }");
        w.println("    tr:nth-child(even) { background-color: #f9f9f9; }");
        w.println("    .CRITICAL { color: #b22222; font-weight: bold; }");
        w.println("    .HIGH     { color: #cc5500; font-weight: bold; }");
        w.println("    .MEDIUM   { color: #e6a000; }");
        w.println("    .LOW      { color: #2e7d32; }");
        w.println("  </style>");
        w.println("</head>");
        w.println("<body>");

        w.printf("<h1>Static Security Analysis Report</h1>%n");
        w.printf("<p>Generated: %s</p>%n", escapeHtml(timestamp));
        w.printf("<p>Total Vulnerabilities Found: <strong>%d</strong></p>%n", vulns.size());

        if (vulns.isEmpty()) {
            w.println("<p>No vulnerabilities detected.</p>");
        } else {
            w.println("<table>");
            w.println("  <thead><tr>");
            w.println("    <th>#</th><th>Type</th><th>File</th><th>Line</th>");
            w.println("    <th>Severity</th><th>Description</th><th>Fix Suggestion</th>");
            w.println("  </tr></thead>");
            w.println("  <tbody>");

            int idx = 1;
            for (Vulnerability v : vulns) {

                // FIX 2: every dynamic value is HTML-escaped before writing
                w.printf("  <tr>%n");
                w.printf("    <td>%d</td>%n", idx++);
                w.printf("    <td>%s</td>%n",         escapeHtml(v.getType()));
                w.printf("    <td>%s</td>%n",         escapeHtml(v.getFile()));
                w.printf("    <td>%d</td>%n",         v.getLine());
                w.printf("    <td class=\"%s\">%s</td>%n",
                        escapeHtml(v.getSeverity()), escapeHtml(v.getSeverity()));
                w.printf("    <td>%s</td>%n",         escapeHtml(v.getDescription()));
                w.printf("    <td>%s</td>%n",         escapeHtml(v.getFixSuggestion()));
                w.printf("  </tr>%n");
            }

            w.println("  </tbody>");
            w.println("</table>");
        }

        w.println("</body></html>");
    }

    /**
     * Escapes the five characters that are significant in HTML contexts.
     * Applied to every dynamic value written into the report to prevent
     * the report itself from being an XSS vector.
     */
    private static String escapeHtml(String input) {

        if (input == null) return "";

        return input
                .replace("&",  "&amp;")   // must be first
                .replace("<",  "&lt;")
                .replace(">",  "&gt;")
                .replace("\"", "&quot;")
                .replace("'",  "&#x27;");
    }
}