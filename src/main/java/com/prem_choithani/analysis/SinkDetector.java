package com.prem_choithani.analysis;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.prem_choithani.rules.PatternLibrary;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects data-flow sinks — points in the code where tainted (user-controlled)
 * data may produce an HTML/XSS vulnerability.
 *
 * FIXES APPLIED (v2 — deduplication and separation of concerns)
 * -------------------------------------------------------------
 * FIX-A: REMOVED detectSqlConcatenation() from detectSinks().
 *   The original code added SQL-keyword concatenations to the same sink
 *   list that XSSRule consumed.  This caused every SQL injection string
 *   (e.g. "SELECT * FROM users WHERE name = '" + name) to be reported
 *   as XSS as well as SQL Injection — doubling every finding.
 *   SQL sinks are detected exclusively by SQLInjectionRule; SinkDetector
 *   is now HTML/XSS-only.
 *
 * FIX-B: ADDED isRootConcatenation() guard to all BinaryExpr loops.
 *   Java's "a" + x + "b" + "c" is stored in the AST as nested pairs:
 *     (((("a" + x) + "b") + "c"))
 *   Without this guard every node in the chain matched independently,
 *   producing N findings for a single vulnerable expression.
 *   The guard skips any BinaryExpr whose direct parent is also a PLUS
 *   BinaryExpr — those inner nodes will be covered by the outermost
 *   report.  Result: exactly 1 finding per vulnerable concatenation.
 */
public class SinkDetector {

    /**
     * Returns HTML/XSS sinks only.  SQL sinks are NOT included here;
     * they are detected by SQLInjectionRule via its own BinaryExpr scan.
     */
    public List<Expression> detectSinks(MethodDeclaration method) {

        List<Expression> sinks = new ArrayList<>();

        detectHtmlConcatenation(method, sinks);
        detectReturnHtml(method, sinks);
        detectResponseEntity(method, sinks);
        detectDangerousAttributes(method, sinks);
        detectResponseWriteSinks(method, sinks);

        return sinks;
    }

    // ---------------------------------------------------------------
    //  FIX-B helper — only report the outermost node of each + chain
    // ---------------------------------------------------------------

    /**
     * Returns true if this BinaryExpr is the ROOT of a concatenation chain.
     *
     * A PLUS BinaryExpr whose parent is also a PLUS BinaryExpr is an inner
     * node of the same chain and will be covered when the parent is reported.
     * Reporting only the root gives one finding per vulnerable expression.
     */
    private static boolean isRootConcatenation(BinaryExpr expr) {
        return expr.getParentNode()
                .filter(p -> p instanceof BinaryExpr
                        && ((BinaryExpr) p).getOperator() == BinaryExpr.Operator.PLUS)
                .isEmpty();  // true = no PLUS parent = this is the root
    }

    // ---------------------------------------------------------------
    //  HTML concatenation sink
    //  Catches: "<div>" + userInput, "onclick='" + userInput + "'", etc.
    // ---------------------------------------------------------------

    private void detectHtmlConcatenation(MethodDeclaration method, List<Expression> sinks) {

        method.findAll(BinaryExpr.class).forEach(expr -> {

            if (expr.getOperator() != BinaryExpr.Operator.PLUS) return;
            if (!isRootConcatenation(expr)) return;      // FIX-B: skip inner nodes

            boolean isHtmlSink = expr.findAll(StringLiteralExpr.class).stream()
                    .anyMatch(lit ->
                            PatternLibrary.HTML_TAG.matcher(lit.getValue()).find()
                                    || PatternLibrary.DANGEROUS_ATTRIBUTE.matcher(lit.getValue()).find());

            if (isHtmlSink) sinks.add(expr);
        });
    }

    // ---------------------------------------------------------------
    //  Return-statement HTML sink
    //  Catches: return "<div>" + userInput;
    // ---------------------------------------------------------------

    private void detectReturnHtml(MethodDeclaration method, List<Expression> sinks) {

        method.findAll(ReturnStmt.class).forEach(ret ->
                ret.getExpression().ifPresent(expr -> {

                    // Walk to the root BinaryExpr if this is a chain
                    boolean isHtmlSink = expr.findAll(StringLiteralExpr.class).stream()
                            .anyMatch(lit ->
                                    PatternLibrary.HTML_TAG.matcher(lit.getValue()).find()
                                            || PatternLibrary.DANGEROUS_ATTRIBUTE.matcher(lit.getValue()).find());

                    if (isHtmlSink) sinks.add(expr);
                })
        );
    }

    // ---------------------------------------------------------------
    //  ResponseEntity builder sink
    //  Checks ResponseEntity.ok(html), .body(html), etc.
    // ---------------------------------------------------------------

    private static final java.util.Set<String> RESPONSE_ENTITY_BUILDERS = java.util.Set.of(
            "ok", "body", "status", "badRequest", "created", "accepted",
            "noContent", "notFound", "unprocessableEntity", "internalServerError"
    );

    private void detectResponseEntity(MethodDeclaration method, List<Expression> sinks) {

        method.findAll(MethodCallExpr.class).forEach(call -> {

            if (!RESPONSE_ENTITY_BUILDERS.contains(call.getNameAsString())) return;

            boolean isHtmlSink = call.getArguments().stream()
                    .flatMap(arg -> arg.findAll(StringLiteralExpr.class).stream())
                    .anyMatch(lit ->
                            PatternLibrary.HTML_TAG.matcher(lit.getValue()).find()
                                    || PatternLibrary.DANGEROUS_ATTRIBUTE.matcher(lit.getValue()).find());

            if (isHtmlSink) sinks.add(call);
        });
    }

    // ---------------------------------------------------------------
    //  Dangerous attribute sink — on* handlers, javascript: URI schemes
    // ---------------------------------------------------------------

    private void detectDangerousAttributes(MethodDeclaration method, List<Expression> sinks) {

        method.findAll(BinaryExpr.class).forEach(expr -> {

            if (expr.getOperator() != BinaryExpr.Operator.PLUS) return;
            if (!isRootConcatenation(expr)) return;      // FIX-B

            boolean hasDangerousAttr = expr.findAll(StringLiteralExpr.class).stream()
                    .anyMatch(lit ->
                            PatternLibrary.DANGEROUS_ATTRIBUTE.matcher(lit.getValue()).find());

            if (hasDangerousAttr) sinks.add(expr);
        });
    }

    // ---------------------------------------------------------------
    //  PrintWriter / HttpServletResponse write sink
    // ---------------------------------------------------------------

    private static final java.util.Set<String> RESPONSE_WRITE_METHODS = java.util.Set.of(
            "print", "println", "write", "append", "format", "printf"
    );

    private void detectResponseWriteSinks(MethodDeclaration method, List<Expression> sinks) {

        method.findAll(MethodCallExpr.class).forEach(call -> {

            if (!RESPONSE_WRITE_METHODS.contains(call.getNameAsString())) return;

            call.getScope().ifPresent(scope -> {

                String scopeStr = scope.toString().toLowerCase();

                if (scopeStr.contains("getwriter")
                        || scopeStr.contains("response")
                        || scopeStr.equals("out")
                        || scopeStr.equals("writer")) {

                    sinks.add(call);
                }
            });
        });
    }
}