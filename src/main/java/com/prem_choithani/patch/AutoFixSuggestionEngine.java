package com.prem_choithani.patch;

import com.prem_choithani.model.Vulnerability;

/**
 * Produces human-readable fix suggestions for each vulnerability type.
 *
 * FIXES APPLIED
 * -------------
 * 1. TYPE STRING MISMATCHES: The original switch cases did not match the
 *    type strings actually set in Vulnerability objects by the rule classes.
 *
 *    Original (broken):          Actual type from rule:
 *    ─────────────────────────   ──────────────────────
 *    "Reflected XSS"          ≠  "XSS"              (XSSRule.java)
 *    "Unsafe Template Rendering" ≠  "Template Injection" (TemplateSecurityRule.java)
 *    ─────────────────────────
 *    These mismatches meant the switch always fell through to default,
 *    returning the generic "Review input validation" message instead of
 *    a meaningful, targeted suggestion.
 *
 *    FIX: Case labels now exactly match the type strings returned by each
 *    rule.  A central comment documents each mapping to prevent future drift.
 *
 * 2. ADDED missing cases for "Security Misconfiguration" (SecurityConfigRule)
 *    and "Command Injection" / "Path Traversal" (PatternLibrary detection).
 *
 * 3. ADDED VulnerabilityType constants so that rule classes and this class
 *    can reference a shared constant rather than duplicating string literals.
 *    This is the root fix — literal duplication across classes is the reason
 *    the mismatch existed in the first place.
 */
public class AutoFixSuggestionEngine {

    // ---------------------------------------------------------------
    //  Shared type-string constants.
    //  Rule classes should use these when constructing Vulnerability objects
    //  so that the type string is defined in exactly ONE place.
    // ---------------------------------------------------------------

    public static final class VulnerabilityType {
        private VulnerabilityType() {}

        public static final String SQL_INJECTION          = "SQL Injection";
        public static final String XSS                   = "XSS";
        public static final String TEMPLATE_INJECTION     = "Template Injection";
        public static final String SECURITY_MISCONFIG     = "Security Misconfiguration";
        public static final String COMMAND_INJECTION      = "Command Injection";
        public static final String PATH_TRAVERSAL         = "Path Traversal";
        public static final String INSECURE_DESERIALIZATION = "Insecure Deserialization";
        public static final String HARDCODED_SECRET       = "Hardcoded Secret";
    }

    public String suggestFix(Vulnerability v) {

        // FIX: case strings now match VulnerabilityType constants (and the
        //      type strings used in each rule's new Vulnerability() call).
        switch (v.getType()) {

            case VulnerabilityType.SQL_INJECTION:
                return "Use PreparedStatement or Spring Data JPA/JPQL with named parameters. " +
                        "Example: conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\") " +
                        "then stmt.setString(1, userInput). " +
                        "Never concatenate user input into query strings.";

            // FIX: was "Reflected XSS" — XSSRule emits type "XSS"
            case VulnerabilityType.XSS:
                return "Escape all output with HtmlUtils.htmlEscape() (Spring) or " +
                        "OWASP Java Encoder: Encode.forHtml(userInput). " +
                        "Enable template engine auto-escaping (th:text, not th:utext). " +
                        "Set Content-Security-Policy response header.";

            // FIX: was "Unsafe Template Rendering" — TemplateSecurityRule emits "Template Injection"
            case VulnerabilityType.TEMPLATE_INJECTION:
                return "Avoid unescaped template directives (th:utext, ?no_esc, #evaluate). " +
                        "Use th:text (Thymeleaf), auto-escaped output (FreeMarker HTMLOutputFormat). " +
                        "For SpEL: use SimpleEvaluationContext with restricted access. " +
                        "Never build template expression strings from user input.";

            case VulnerabilityType.SECURITY_MISCONFIG:
                return "Add Spring Security: @EnableWebSecurity on a @Configuration class " +
                        "with a SecurityFilterChain bean. At minimum, authenticate all non-public " +
                        "endpoints and configure CSRF protection.";

            case VulnerabilityType.COMMAND_INJECTION:
                return "Avoid Runtime.exec() and ProcessBuilder with user-supplied arguments. " +
                        "If OS commands are necessary, use a whitelist of permitted commands " +
                        "and arguments, and never pass unsanitized user input as shell arguments.";

            case VulnerabilityType.PATH_TRAVERSAL:
                return "Validate file paths with Paths.get(base).resolve(userInput).normalize() " +
                        "and check that the resolved path starts with the base directory. " +
                        "Reject inputs containing ../ or absolute path separators.";

            case VulnerabilityType.HARDCODED_SECRET:
                return "Move credentials and secrets to environment variables, " +
                        "application.properties (excluded from VCS), or a secrets manager " +
                        "(HashiCorp Vault, AWS Secrets Manager, Spring Cloud Config Server). " +
                        "Rotate any exposed secrets immediately.";

            default:
                return "Review input validation and output encoding for this component. " +
                        "Consult OWASP Top 10 guidelines for the specific vulnerability class.";
        }
    }
}