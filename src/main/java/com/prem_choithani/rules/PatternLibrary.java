package com.prem_choithani.rules;

import java.util.regex.Pattern;

/**
 * Central registry for all security-detection regex patterns.
 *
 * DESIGN RATIONALE
 * ----------------
 * Previously, every rule class contained ad-hoc string literals such as
 *   value.contains("select ")  or  value.contains("<div")
 * These are fragile, case-sensitive, and extremely incomplete.
 * Centralising patterns here:
 *   1. Makes coverage audits trivial (one place to check / extend).
 *   2. Enables case-insensitive and boundary-aware matching.
 *   3. Decouples detection logic from the literal form of the keyword.
 *   4. Supports all MVC / REST frameworks, not just Spring.
 *
 * PATTERN SCOPE
 * -------------
 * All patterns are designed to work on *Java source code strings*, i.e. the
 * text of string literals that appear in the compiled AST.  They are NOT
 * applied to raw HTTP traffic or template files.
 */
public final class PatternLibrary {

    private PatternLibrary() { /* utility class */ }

    // =========================================================
    //  SQL INJECTION  (used by SQLInjectionRule, SinkDetector)
    // =========================================================

    /**
     * Matches SQL DML/DDL keywords that indicate a SQL query is being
     * concatenated from a string literal.
     *
     * Covers: SELECT, INSERT INTO, UPDATE … SET, DELETE FROM, DROP,
     *         TRUNCATE, ALTER, EXEC / EXECUTE (stored procs), UNION,
     *         MERGE, CALL, CREATE, GRANT, REVOKE.
     *
     * IMPORTANT — INSERT requires INTO after it.
     *   Without this, the regex matches "insert" inside "th:insert=\"…\""
     *   (Thymeleaf attribute names) because the ":" before "insert" acts
     *   as a word boundary, producing false SQL Injection findings in
     *   template controller files.
     *   Requiring \s+INTO matches only real SQL INSERT statements.
     *
     * Word-boundary anchors (\b) prevent false positives on variable names
     * like "updatedAt" (contains "update") or "selector" (contains "select").
     *
     * CASE_INSENSITIVE so both upper- and lower-case SQL is caught.
     */
    public static final Pattern SQL_KEYWORD = Pattern.compile(
            "(?i)\\b(SELECT" +
                    "|INSERT\\s+INTO" +          // FIX: requires INTO — prevents th:insert match
                    "|UPDATE\\s" +               // UPDATE must be followed by whitespace (table name)
                    "|DELETE\\s+FROM|DELETE\\s" +
                    "|DROP\\s+(TABLE|DATABASE|INDEX|VIEW|PROCEDURE)" +
                    "|TRUNCATE\\s+(TABLE\\s+)?" +
                    "|ALTER\\s+(TABLE|DATABASE|COLUMN)" +
                    "|EXEC(UTE)?\\s" +
                    "|UNION\\s+SELECT" +
                    "|MERGE\\s+INTO|MERGE\\s" +
                    "|CALL\\s" +
                    "|CREATE\\s+(TABLE|DATABASE|INDEX|VIEW|PROCEDURE|TRIGGER)" +
                    "|GRANT\\s" +
                    "|REVOKE\\s" +
                    "|REPLACE\\s+INTO)\\b",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Detects classic SQL comment injection suffixes, e.g.:
     *   " OR 1=1 --"   " OR '1'='1"   "'; DROP TABLE users; --"
     *
     * Useful as a secondary signal when taint data is present.
     */
    public static final Pattern SQL_COMMENT_INJECTION = Pattern.compile(
            "(--\\s*$|#\\s*$|/\\*.*?\\*/|;\\s*--)"
    );

    // =========================================================
    //  XSS / HTML SINK  (used by SinkDetector, XSSRule)
    // =========================================================

    /**
     * Matches the opening of any HTML tag that can carry executable content
     * or redirect a browser.  This is intentionally broader than just
     * <script> because XSS has many vectors.
     *
     * Includes: script, iframe, img (onerror), a (href=javascript:),
     *           form (action), input, button, object, embed, link, meta,
     *           style, svg, math (MathML), base, frame, frameset, applet,
     *           video, audio, canvas, template, slot, details, summary,
     *           and generic block/inline elements that are commonly abused.
     *
     * The (?:[\s>/"']) after the tag name prevents partial matches like
     * <paragraph being caught as <p>.
     */
    public static final Pattern HTML_TAG = Pattern.compile(
            "(?i)<\\s*(?:script|iframe|img|a|form|input|button|object|embed" +
                    "|link|meta|style|div|span|p|h[1-6]|body|html|head" +
                    "|svg|math|base|frame(?:set)?|applet|video|audio" +
                    "|canvas|template|slot|details|summary|marquee|blink" +
                    "|isindex|layer|ilayer|xml|bgsound|listing|xmp|plaintext" +
                    ")(?:[\\s>/\"']|$)"
    );

    /**
     * Matches dangerous HTML attribute patterns that can carry JavaScript,
     * regardless of the enclosing tag.  Critical for detecting XSS payloads
     * that are injected into existing tag attributes.
     *
     * Covers: event handlers (onclick, onload, onerror, …),
     *         javascript: / vbscript: URI schemes,
     *         data:text/html payloads,
     *         CSS expression() (legacy IE).
     */
    public static final Pattern DANGEROUS_ATTRIBUTE = Pattern.compile(
            "(?i)(\\bon\\w+\\s*=" +
                    "|javascript\\s*:" +
                    "|vbscript\\s*:" +
                    "|data\\s*:\\s*text/html" +
                    "|expression\\s*\\(" +
                    "|&#[xX]?[0-9a-fA-F]+;)"  // HTML-encoded evasion
    );

    // =========================================================
    //  TEMPLATE INJECTION  (used by TemplateSecurityRule)
    // =========================================================

    /**
     * Thymeleaf — dangerous directives that render unescaped content.
     *
     * th:utext     — unescaped text (direct XSS vector)
     * th:insert    — fragment insertion (SSTI if fragment name is user-controlled)
     * th:replace   — same risk as th:insert
     * th:href      — link injection if value is user-controlled
     * th:src       — script/image source injection
     * th:action    — form action injection
     * th:attr      — arbitrary attribute override
     * th:onclick / th:on* — event handler injection
     * th:fragment with __${…}__ — preprocessed expression injection
     */
    public static final Pattern THYMELEAF_DANGEROUS = Pattern.compile(
            "(?i)\\bth:(utext|insert|replace|href|src|action|attr" +
                    "|onclick|ondblclick|onsubmit|onload|onerror" +
                    "|style|classappend|attrappend)\\s*="
    );

    /**
     * Thymeleaf inline expression injection.
     * [[...]] renders as escaped text by default but [(…)] renders UNESCAPED.
     * __${…}__ is the pre-processing expression — extremely dangerous.
     */
    public static final Pattern THYMELEAF_INLINE_UNSAFE = Pattern.compile(
            "(\\[\\(.*?\\)\\]|__\\$\\{.*?\\}__)"
    );

    /**
     * FreeMarker — dangerous directives.
     *
     * ?no_esc          — disables auto-escaping on an expression
     * <#include …>     — file inclusion
     * <#import …>      — namespace import (can load remote templates)
     * <#assign …>      — variable assignment (useful in chain attacks)
     * ${…?interpret}   — interprets a string as FreeMarker template (RCE risk)
     * freemarker.template.utility.Execute — known RCE gadget class
     */
    public static final Pattern FREEMARKER_DANGEROUS = Pattern.compile(
            "(?i)(\\?no_esc" +
                    "|<#\\s*(include|import|assign|setting)" +
                    "|\\$\\{[^}]+\\?interpret\\}" +
                    "|freemarker\\.template\\.utility\\.Execute)"
    );

    /**
     * Apache Velocity — dangerous directives.
     *
     * #include / #parse — file inclusion
     * #evaluate         — evaluates a string as Velocity template (SSTI/RCE)
     * #define / #macro  — reusable block definitions (chain attack step)
     * #set with external value — taint propagation
     */
    public static final Pattern VELOCITY_DANGEROUS = Pattern.compile(
            "(?i)#\\s*(include|parse|evaluate|define|macro)\\s*\\("
    );

    /**
     * Pebble / Jinja2-style (used via some Java template bridges) and
     * generic SSTI fingerprints.
     *
     * {{…}}        — Mustache / Pebble / Jinja2 unescaped output
     * {%…%}        — Jinja2 / Twig control block
     * <%= … %>     — JSP scriptlet expression
     * <%! … %>     — JSP declaration block
     * <%-          — EJS unescaped output
     */
    public static final Pattern GENERIC_SSTI = Pattern.compile(
            "(\\{\\{[^}]+\\}\\}" +
                    "|\\{%[^%]+%\\}" +
                    "|<%[=!-]" +
                    "|\\$\\{[^}]+\\})"     // generic EL / SpEL / OGNL expression
    );

    /**
     * Spring Expression Language (SpEL) injection.
     * Dangerous when user input lands in @Value, ExpressionParser.parseExpression,
     * or any SpEL-evaluated annotation attribute.
     */
    public static final Pattern SPEL_INJECTION = Pattern.compile(
            "(?i)(parseExpression\\s*\\(" +
                    "|ExpressionParser" +
                    "|SpelExpressionParser" +
                    "|StandardEvaluationContext" +
                    "|@Value\\s*\\(\\s*\"#\\{)"
    );

    // =========================================================
    //  COMMAND INJECTION  (bonus — common in REST back-ends)
    // =========================================================

    /**
     * Detects patterns where user input may reach OS command execution.
     *
     * Runtime.exec(), ProcessBuilder, and common shell-related methods.
     */
    public static final Pattern COMMAND_EXECUTION = Pattern.compile(
            "(?i)(Runtime\\.getRuntime\\(\\)\\.exec" +
                    "|new\\s+ProcessBuilder" +
                    "|ProcessBuilder\\.command" +
                    "|ScriptEngine.*eval" +
                    "|groovy\\.lang\\.GroovyShell)"
    );

    // =========================================================
    //  PATH TRAVERSAL  (REST file-serving endpoints)
    // =========================================================

    /**
     * Detects path traversal sequences in string literals or user-controlled
     * values.  Covers both Unix and Windows separators and URL-encoded forms.
     */
    public static final Pattern PATH_TRAVERSAL = Pattern.compile(
            "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%252e%252e%252f)",
            Pattern.CASE_INSENSITIVE
    );

    // =========================================================
    //  SENSITIVE DATA HARDCODING  (passwords, secrets, tokens)
    // =========================================================

    /**
     * Detects variable / field names that strongly suggest a hardcoded secret.
     * Applied to variable declaration nodes, not to values.
     *
     * Intentionally broad — tuned for low false-negative rate in a SAST tool.
     */
    public static final Pattern HARDCODED_SECRET_VARNAME = Pattern.compile(
            "(?i)(password|passwd|secret|api[_-]?key|token|credentials" +
                    "|access[_-]?key|private[_-]?key|auth[_-]?token|client[_-]?secret)"
    );

    /**
     * Detects string literal values that look like secrets (high entropy or
     * well-known secret patterns).
     *
     * Covers: AWS access keys, GitHub tokens, JWT headers, hex/base64 blobs.
     */
    public static final Pattern HARDCODED_SECRET_VALUE = Pattern.compile(
            "(AKIA[0-9A-Z]{16}" +                   // AWS Access Key
                    "|ghp_[0-9A-Za-z]{36}" +                // GitHub PAT
                    "|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\." + // JWT
                    "|[0-9a-fA-F]{32,})"                    // generic hex secret
    );
}