package com.prem_choithani.core;

import com.prem_choithani.model.Vulnerability;
import com.prem_choithani.parser.ASTBuilder;
import com.prem_choithani.rules.*;
import com.prem_choithani.scanner.ProjectScanner;
import com.github.javaparser.ast.CompilationUnit;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Central analysis engine: scans a project directory, parses each Java
 * file into an AST, runs all security rules, and collects vulnerabilities.
 *
 * FIXES APPLIED
 * -------------
 * 1. REMOVED commented-out debug System.out.println / cu.findAll blocks.
 *    Dead code left in source increases cognitive overhead and indicates
 *    the codebase lacks proper logging infrastructure.
 *
 * 2. REPLACED System.out.println("Analysis failed") with a proper Logger.
 *    Console output is not appropriate for a library/engine component;
 *    it prevents callers from redirecting or filtering log output.
 *
 * 3. WIRED the new SecurityConfigRule API.
 *    The original code called SecurityConfigRule.finalizeCheck() which read
 *    from a static boolean that was never reset between runs.
 *    Now we accumulate isSecurityConfigPresent() per-file and pass the
 *    result to finalizeCheck(boolean).
 *
 * 4. Per-file parse failures are logged with the filename and the error
 *    message; the engine continues scanning remaining files (fail-open).
 */
public class AnalyzerEngine {

    private static final Logger LOGGER = Logger.getLogger(AnalyzerEngine.class.getName());

    private final ProjectScanner scanner;
    private final ASTBuilder parser;
    private final List<SecurityRule> rules;
    private final SecurityConfigRule securityConfigRule;

    public AnalyzerEngine() {

        scanner = new ProjectScanner();
        parser = new ASTBuilder();
        securityConfigRule = new SecurityConfigRule();

        rules = new ArrayList<>();
        rules.add(new XSSRule());
        rules.add(new SQLInjectionRule());
        rules.add(new TemplateSecurityRule());
        rules.add(new HardcodedSecretRule());
        rules.add(securityConfigRule);
    }

    public List<Vulnerability> analyzeProject(String projectPath) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // FIX: track security config presence without static mutable state
        boolean securityConfigFound = false;

        try {
            List<File> javaFiles = scanner.scanProject(projectPath);

            for (File file : javaFiles) {

                CompilationUnit cu = null;

                try {
                    cu = parser.build(file);
                } catch (RuntimeException e) {
                    // FIX: per-file parse error is logged with context; analysis continues
                    LOGGER.log(Level.WARNING,
                            "AST parse failed for file [{0}]: {1}",
                            new Object[]{ file.getName(), e.getMessage() });
                    continue;
                }

                for (SecurityRule rule : rules) {
                    List<Vulnerability> detected = rule.analyze(cu, file.getName());
                    vulnerabilities.addAll(detected);
                }

                // FIX: accumulate per-file security config presence
                if (securityConfigRule.isSecurityConfigPresent(cu)) {
                    securityConfigFound = true;
                }
            }

        } catch (Exception e) {
            // FIX: full stack trace goes to logger, not stdout
            LOGGER.log(Level.SEVERE, "Project analysis failed for path: " + projectPath, e);
        }

        // FIX: finalizeCheck now receives the accumulated boolean, not static field
        vulnerabilities.addAll(SecurityConfigRule.finalizeCheck(securityConfigFound));

        return vulnerabilities;
    }
}