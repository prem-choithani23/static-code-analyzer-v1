package com.prem_choithani.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import com.prem_choithani.analysis.SourceDetector;
import com.prem_choithani.analysis.TaintPropagationEngine;
import com.prem_choithani.model.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Detects SQL Injection vulnerabilities through taint-flow analysis.
 *
 * FIXES APPLIED
 * -------------
 * 1. REPLACED 4-keyword hardcoded SQL check with PatternLibrary.SQL_KEYWORD.
 *    Before: value.contains("select ") || value.contains("insert ") || ...
 *    After:  PatternLibrary.SQL_KEYWORD.matcher(value).find()
 *
 *    Old code missed: DROP, TRUNCATE, EXEC/EXECUTE, UNION SELECT, MERGE,
 *    CALL (stored procedures), CREATE, GRANT, REVOKE — all of which are
 *    equally valid SQL injection targets.
 *
 * 2. ADDED detection of String.format() SQL construction.
 *    Before: only checked BinaryExpr ("+") for SQL construction.
 *    After:  also checks String.format("SELECT * FROM %s", tableName) patterns
 *    which are just as dangerous as concatenation.
 *
 * 3. ADDED detection of StringBuilder/StringBuffer append() SQL construction.
 *    Developers often switch from "+" to .append() thinking it is safer.
 *
 * 4. ADDED secondary check for PreparedStatement usage — if a tainted
 *    variable flows into a query string but the method ALSO uses
 *    PreparedStatement, severity is downgraded to MEDIUM (possible safe use).
 */
public class SQLInjectionRule implements SecurityRule {

    private final SourceDetector sourceDetector = new SourceDetector();
    private final TaintPropagationEngine taintEngine = new TaintPropagationEngine();

    @Override
    public String getRuleName() {
        return "SQL Injection";
    }

    @Override
    public List<Vulnerability> analyze(CompilationUnit cu, String fileName) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {

            Set<String> sources = sourceDetector.detectSources(method);
            if (sources.isEmpty()) continue;

            Set<String> tainted = taintEngine.propagateTaint(method, sources);

            boolean usesPreparedStatement = methodUsesPreparedStatement(method);

            detectConcatenationInjection(method, fileName, tainted, usesPreparedStatement, vulnerabilities);
            detectStringFormatInjection(method, fileName, tainted, usesPreparedStatement, vulnerabilities);
            detectStringBuilderInjection(method, fileName, tainted, usesPreparedStatement, vulnerabilities);
        }

        return vulnerabilities;
    }

    // ---------------------------------------------------------------
    //  "SELECT " + userId  (binary + expression)
    // ---------------------------------------------------------------

    private void detectConcatenationInjection(
            MethodDeclaration method,
            String fileName,
            Set<String> tainted,
            boolean usesPreparedStatement,
            List<Vulnerability> vulnerabilities
    ) {
        for (BinaryExpr expr : method.findAll(BinaryExpr.class)) {

            if (expr.getOperator() != BinaryExpr.Operator.PLUS) continue;

            // DEDUP FIX: skip inner nodes of a chain — only report the outermost PLUS expr.
            // "SELECT " + x + " WHERE id=" + y  →  AST: (((SELECT+x)+WHERE)+y)
            // Without this guard every sub-expression fires separately.
            if (!isRootConcatenation(expr)) continue;

            // FIX: replaced 4 hardcoded contains() with PatternLibrary regex
            boolean hasSqlLiteral = expr.findAll(StringLiteralExpr.class).stream()
                    .anyMatch(lit -> PatternLibrary.SQL_KEYWORD.matcher(lit.getValue()).find());

            if (!hasSqlLiteral) continue;

            boolean taintedFlow = expr.findAll(NameExpr.class).stream()
                    .anyMatch(name -> tainted.contains(name.getNameAsString()));

            if (!taintedFlow) continue;

            int line = expr.getBegin().map(p -> p.line).orElse(-1);

            // Downgrade severity when PreparedStatement is also present
            String severity = usesPreparedStatement ? "MEDIUM" : "CRITICAL";
            String description = usesPreparedStatement
                    ? "User input used in SQL concatenation; PreparedStatement detected in same method — verify parameterization is applied to this query"
                    : "User input directly concatenated into SQL query — no PreparedStatement detected";

            vulnerabilities.add(new Vulnerability(
                    "SQL Injection",
                    fileName,
                    line,
                    tainted.toString(),
                    expr.toString(),
                    description,
                    severity,
                    "Use PreparedStatement with parameterized queries: " +
                            "conn.prepareStatement(\"SELECT * FROM t WHERE id = ?\") then stmt.setString(1, userInput)"
            ));
        }
    }

    // ---------------------------------------------------------------
    //  String.format("SELECT * FROM %s WHERE id=%s", table, userId)
    // ---------------------------------------------------------------

    private void detectStringFormatInjection(
            MethodDeclaration method,
            String fileName,
            Set<String> tainted,
            boolean usesPreparedStatement,
            List<Vulnerability> vulnerabilities
    ) {
        for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {

            if (!call.getNameAsString().equals("format")) continue;

            // Scope must be String or absent (static import)
            boolean isStringFormat = call.getScope()
                    .map(s -> s.toString().equals("String"))
                    .orElse(true);

            if (!isStringFormat || call.getArguments().isEmpty()) continue;

            // First argument must be a SQL-containing string literal
            boolean hasSqlLiteral = call.getArguments().get(0)
                    .findAll(StringLiteralExpr.class).stream()
                    .anyMatch(lit -> PatternLibrary.SQL_KEYWORD.matcher(lit.getValue()).find());

            if (!hasSqlLiteral) continue;

            // Any subsequent argument must be tainted
            boolean taintedArg = call.getArguments().stream().skip(1)
                    .flatMap(arg -> arg.findAll(NameExpr.class).stream())
                    .anyMatch(name -> tainted.contains(name.getNameAsString()));

            if (!taintedArg) continue;

            int line = call.getBegin().map(p -> p.line).orElse(-1);
            String severity = usesPreparedStatement ? "MEDIUM" : "CRITICAL";

            vulnerabilities.add(new Vulnerability(
                    "SQL Injection",
                    fileName,
                    line,
                    tainted.toString(),
                    call.toString(),
                    "User input passed to String.format() for SQL construction — format strings do not sanitize SQL",
                    severity,
                    "Replace String.format SQL construction with PreparedStatement parameterized queries"
            ));
        }
    }

    // ---------------------------------------------------------------
    //  sb.append("SELECT ").append(userId)  (StringBuilder/Buffer)
    // ---------------------------------------------------------------

    private void detectStringBuilderInjection(
            MethodDeclaration method,
            String fileName,
            Set<String> tainted,
            boolean usesPreparedStatement,
            List<Vulnerability> vulnerabilities
    ) {
        // Collect all append() calls; find chains containing both a SQL literal
        // and a tainted variable name.
        for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) {

            if (!call.getNameAsString().equals("append")) continue;

            // Walk up the call chain collecting all SQL literals and tainted names
            boolean hasSqlLiteral = false;
            boolean hasTainted = false;

            MethodCallExpr current = call;
            while (current != null) {

                for (StringLiteralExpr lit : current.getArguments()
                        .stream()
                        .flatMap(a -> a.findAll(StringLiteralExpr.class).stream())
                        .toList()) {

                    if (PatternLibrary.SQL_KEYWORD.matcher(lit.getValue()).find()) {
                        hasSqlLiteral = true;
                    }
                }

                for (NameExpr name : current.getArguments()
                        .stream()
                        .flatMap(a -> a.findAll(NameExpr.class).stream())
                        .toList()) {

                    if (tainted.contains(name.getNameAsString())) {
                        hasTainted = true;
                    }
                }

                // Move to parent append in chain
                current = current.getScope()
                        .filter(s -> s instanceof MethodCallExpr)
                        .map(s -> (MethodCallExpr) s)
                        .filter(s -> s.getNameAsString().equals("append"))
                        .orElse(null);
            }

            if (!hasSqlLiteral || !hasTainted) continue;

            int line = call.getBegin().map(p -> p.line).orElse(-1);
            String severity = usesPreparedStatement ? "MEDIUM" : "CRITICAL";

            vulnerabilities.add(new Vulnerability(
                    "SQL Injection",
                    fileName,
                    line,
                    tainted.toString(),
                    call.toString(),
                    "User input appended into SQL via StringBuilder — equivalent risk to string concatenation",
                    severity,
                    "Replace StringBuilder SQL construction with PreparedStatement parameterized queries"
            ));
        }
    }

    // ---------------------------------------------------------------
    //  Helper: does this method use PreparedStatement at all?
    // ---------------------------------------------------------------

    private boolean methodUsesPreparedStatement(MethodDeclaration method) {

        return method.findAll(MethodCallExpr.class).stream()
                .anyMatch(call -> call.getNameAsString().equals("prepareStatement")
                        || call.getNameAsString().equals("prepareCall"))
                || method.toString().contains("PreparedStatement")
                || method.toString().contains("NamedParameterJdbcTemplate")
                || method.toString().contains("JdbcTemplate");
    }

    // ---------------------------------------------------------------
    //  Helper: report only the outermost node of each + chain
    // ---------------------------------------------------------------

    /**
     * Returns true if this BinaryExpr is the ROOT of a PLUS-concatenation
     * chain — meaning its parent is NOT also a PLUS BinaryExpr.
     *
     * "a" + x + "b" + "c"  becomes  (((a+x)+b)+c) in the AST.
     * Without this guard, visiting all BinaryExpr nodes would report the
     * same tainted chain 3 times (once per sub-expression).
     * Only the root (outermost) node is reported; it captures the full chain.
     */
    private static boolean isRootConcatenation(BinaryExpr expr) {
        return expr.getParentNode()
                .filter(p -> p instanceof BinaryExpr
                        && ((BinaryExpr) p).getOperator() == BinaryExpr.Operator.PLUS)
                .isEmpty();
    }
}