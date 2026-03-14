package com.prem_choithani.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.prem_choithani.model.Vulnerability;
import com.prem_choithani.patch.AutoFixSuggestionEngine.VulnerabilityType;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects hardcoded secrets (passwords, API keys, tokens) in Java source.
 *
 * This is a BONUS rule made possible by PatternLibrary.  It covers a very
 * common finding in REST/MVC applications where credentials are hardcoded
 * rather than externalised to environment variables or secrets managers.
 *
 * DETECTION STRATEGY
 * ------------------
 * Two complementary signals are checked:
 *
 * 1. Variable NAME heuristic (PatternLibrary.HARDCODED_SECRET_VARNAME):
 *    A field or variable whose name looks like a credential (password,
 *    apiKey, secret, authToken, …) AND whose value is a non-empty string
 *    literal is flagged.
 *
 * 2. Value PATTERN heuristic (PatternLibrary.HARDCODED_SECRET_VALUE):
 *    A string literal whose value matches known secret formats (AWS keys,
 *    GitHub PATs, JWTs, long hex strings) is flagged regardless of the
 *    variable name.
 *
 * FALSE POSITIVE MITIGATION
 * -------------------------
 * • Empty strings ("") and single-character strings are skipped.
 * • Placeholder strings ("your-password-here", "changeme", "TODO") are
 *   flagged as LOW severity rather than HIGH — they indicate incomplete
 *   configuration, not necessarily a real secret.
 */
public class HardcodedSecretRule implements SecurityRule {

    private static final java.util.Set<String> PLACEHOLDER_HINTS = java.util.Set.of(
            "changeme", "change_me", "your-password", "your_password",
            "placeholder", "example", "test", "todo", "fixme", "replace"
    );

    @Override
    public String getRuleName() {
        return VulnerabilityType.HARDCODED_SECRET;
    }

    @Override
    public List<Vulnerability> analyze(CompilationUnit cu, String fileName) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Check class/instance field declarations
        for (FieldDeclaration field : cu.findAll(FieldDeclaration.class)) {

            for (VariableDeclarator var : field.getVariables()) {

                var.getInitializer().ifPresent(init -> {

                    init.findAll(StringLiteralExpr.class).forEach(literal -> {

                        String varName  = var.getNameAsString();
                        String value    = literal.getValue();

                        if (value.isEmpty() || value.length() < 2) return;

                        int line = literal.getBegin().map(p -> p.line).orElse(-1);

                        // Signal 1: suspicious variable name with a string value
                        if (PatternLibrary.HARDCODED_SECRET_VARNAME
                                .matcher(varName).find()) {

                            boolean isPlaceholder = PLACEHOLDER_HINTS.stream()
                                    .anyMatch(hint -> value.toLowerCase().contains(hint));

                            String severity = isPlaceholder ? "LOW" : "HIGH";

                            vulnerabilities.add(new Vulnerability(
                                    VulnerabilityType.HARDCODED_SECRET,
                                    fileName,
                                    line,
                                    "Field: " + varName,
                                    "String literal: \"" + redact(value) + "\"",
                                    "Possible hardcoded credential in field '" + varName +
                                            "'. Secrets should never be stored in source code.",
                                    severity,
                                    "Move to environment variable (System.getenv()), " +
                                            "application.properties (excluded from VCS), " +
                                            "or a secrets manager (Vault, AWS SSM, Azure Key Vault)."
                            ));
                        }

                        // Signal 2: value matches a known secret format
                        if (PatternLibrary.HARDCODED_SECRET_VALUE
                                .matcher(value).find()) {

                            vulnerabilities.add(new Vulnerability(
                                    VulnerabilityType.HARDCODED_SECRET,
                                    fileName,
                                    line,
                                    "Field: " + varName,
                                    "String literal matching secret pattern",
                                    "String literal matches a known secret format " +
                                            "(AWS key, GitHub PAT, JWT, or high-entropy hex). " +
                                            "If this is a real credential, it must be rotated immediately.",
                                    "CRITICAL",
                                    "Rotate this credential immediately. " +
                                            "Store secrets in environment variables or a secrets manager."
                            ));
                        }
                    });
                });
            }
        }

        return vulnerabilities;
    }

    /** Redacts most of the secret value in log/report output. */
    private static String redact(String value) {
        if (value.length() <= 4) return "****";
        return value.substring(0, 2) + "****" + value.substring(value.length() - 2);
    }
}