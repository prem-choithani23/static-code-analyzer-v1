package com.prem_choithani.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.prem_choithani.model.Vulnerability;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects Server-Side Template Injection (SSTI) and unsafe template
 * rendering patterns across all major Java template engines.
 *
 * FIXES APPLIED
 * -------------
 * 1. OLD CODE only checked for Thymeleaf th:utext / th:insert / th:replace
 *    with a single regex.  This missed:
 *      • FreeMarker ?no_esc, <#include>, ${…?interpret}
 *      • Apache Velocity #include, #evaluate, #parse, #macro
 *      • SpEL injection via ExpressionParser / @Value("#{…}")
 *      • Generic SSTI patterns: {{…}}, {%…%}, <%=…%>
 *      • Thymeleaf unescaped inline [(…)] and __${…}__ pre-processing
 *
 * 2. REPLACED the single pattern with PatternLibrary constants that cover
 *    all the above cases.  Each match produces a typed vulnerability with
 *    the correct engine name and a targeted fix suggestion.
 *
 * 3. Each detection method is isolated — adding a new template engine
 *    requires only adding a PatternLibrary constant and one method call
 *    in analyze().
 */
public class TemplateSecurityRule implements SecurityRule {

    @Override
    public String getRuleName() {
        return "Template Injection";
    }

    @Override
    public List<Vulnerability> analyze(CompilationUnit cu, String fileName) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String code = expr.toString();
            int line = expr.getBegin().map(p -> p.line).orElse(-1);

            checkThymeleafDangerous(code, line, fileName, vulnerabilities);
            checkThymeleafInlineUnsafe(code, line, fileName, vulnerabilities);
            checkFreeMarkerDangerous(code, line, fileName, vulnerabilities);
            checkVelocityDangerous(code, line, fileName, vulnerabilities);
            checkSpelInjection(code, line, fileName, vulnerabilities);
            checkGenericSsti(code, line, fileName, vulnerabilities);
        });

        return vulnerabilities;
    }

    // ---------------------------------------------------------------
    //  Thymeleaf — th:utext, th:insert, th:replace, th:href, th:attr …
    // ---------------------------------------------------------------

    private void checkThymeleafDangerous(
            String code, int line, String fileName, List<Vulnerability> out) {

        if (!PatternLibrary.THYMELEAF_DANGEROUS.matcher(code).find()) return;

        out.add(new Vulnerability(
                "Template Injection",
                fileName,
                line,
                "Template expression",
                "Thymeleaf directive",
                "Dangerous Thymeleaf directive detected — th:utext / th:insert / th:replace " +
                        "or dynamic attribute binding renders content without escaping.",
                "HIGH",
                "Replace th:utext with th:text (HTML-escapes output). " +
                        "For th:insert/th:replace ensure fragment names are never user-controlled. " +
                        "For attribute bindings prefer th:classappend or dedicated safe directives."
        ));
    }

    // ---------------------------------------------------------------
    //  Thymeleaf — unescaped inline [(…)] and pre-processed __${…}__
    // ---------------------------------------------------------------

    private void checkThymeleafInlineUnsafe(
            String code, int line, String fileName, List<Vulnerability> out) {

        if (!PatternLibrary.THYMELEAF_INLINE_UNSAFE.matcher(code).find()) return;

        out.add(new Vulnerability(
                "Template Injection",
                fileName,
                line,
                "Template inline expression",
                "Thymeleaf unescaped inline or pre-processed expression",
                "Unescaped Thymeleaf inline expression detected. [(…)] outputs raw HTML; " +
                        "__${…}__ pre-processes expressions before evaluation (SSTI/RCE risk).",
                "CRITICAL",
                "Use [[…]] (escaped inline) instead of [(…)]. " +
                        "Never use __${userInput}__ — pre-processing allows arbitrary SpEL execution."
        ));
    }

    // ---------------------------------------------------------------
    //  FreeMarker — ?no_esc, <#include>, ${…?interpret}
    // ---------------------------------------------------------------

    private void checkFreeMarkerDangerous(
            String code, int line, String fileName, List<Vulnerability> out) {

        if (!PatternLibrary.FREEMARKER_DANGEROUS.matcher(code).find()) return;

        out.add(new Vulnerability(
                "Template Injection",
                fileName,
                line,
                "Template expression",
                "FreeMarker directive",
                "Dangerous FreeMarker directive detected. ?no_esc disables auto-escaping; " +
                        "<#include>/<#import> can load arbitrary files; ?interpret evaluates strings as " +
                        "FreeMarker templates (Remote Code Execution risk).",
                "CRITICAL",
                "Enable auto-escaping globally in FreeMarker configuration " +
                        "(freemarker.core.HTMLOutputFormat). Remove ?no_esc. " +
                        "Validate and whitelist all template file names used with <#include>. " +
                        "Never call ?interpret on user-controlled data."
        ));
    }

    // ---------------------------------------------------------------
    //  Apache Velocity — #include, #evaluate, #parse, #macro
    // ---------------------------------------------------------------

    private void checkVelocityDangerous(
            String code, int line, String fileName, List<Vulnerability> out) {

        if (!PatternLibrary.VELOCITY_DANGEROUS.matcher(code).find()) return;

        out.add(new Vulnerability(
                "Template Injection",
                fileName,
                line,
                "Template expression",
                "Velocity directive",
                "Dangerous Apache Velocity directive detected. #include/#parse allows file " +
                        "inclusion; #evaluate renders a string as a Velocity template at runtime " +
                        "(SSTI / potential RCE); #macro can be abused in chain attacks.",
                "HIGH",
                "Never pass user-controlled strings to #evaluate or #parse. " +
                        "Whitelist permitted template file names. " +
                        "Use Velocity SecureUberspector to restrict accessible methods."
        ));
    }

    // ---------------------------------------------------------------
    //  SpEL injection — ExpressionParser, @Value("#{…}")
    // ---------------------------------------------------------------

    private void checkSpelInjection(
            String code, int line, String fileName, List<Vulnerability> out) {

        if (!PatternLibrary.SPEL_INJECTION.matcher(code).find()) return;

        out.add(new Vulnerability(
                "Template Injection",
                fileName,
                line,
                "SpEL expression",
                "Spring Expression Language evaluation",
                "SpEL injection risk detected. parseExpression() / StandardEvaluationContext " +
                        "evaluated on user-controlled data allows arbitrary Java method invocation " +
                        "(full RCE). @Value(\"#{…}\") is safe only with static strings.",
                "CRITICAL",
                "Use SimpleEvaluationContext instead of StandardEvaluationContext — it restricts " +
                        "accessible classes. Never build SpEL expression strings from user input. " +
                        "If dynamic evaluation is required, use an allowlist of permitted expressions."
        ));
    }

    // ---------------------------------------------------------------
    //  Generic SSTI — {{…}}, {%…%}, <%=…%>, ${…}
    // ---------------------------------------------------------------

    private void checkGenericSsti(
            String code, int line, String fileName, List<Vulnerability> out) {

        if (!PatternLibrary.GENERIC_SSTI.matcher(code).find()) return;

        out.add(new Vulnerability(
                "Template Injection",
                fileName,
                line,
                "Generic template expression",
                "Template expression syntax",
                "Generic template expression syntax detected ({{…}}, {%…%}, <%=…%>, ${…}). " +
                        "If user-controlled data reaches a template engine evaluation context this " +
                        "can lead to Server-Side Template Injection and Remote Code Execution.",
                "HIGH",
                "Identify which template engine processes this expression. " +
                        "Enable strict auto-escaping. " +
                        "Separate user data from template logic — never concatenate user input into " +
                        "template strings; always pass data as model attributes."
        ));
    }
}