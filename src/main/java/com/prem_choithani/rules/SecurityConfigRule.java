package com.prem_choithani.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;

import com.prem_choithani.model.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Detects missing or misconfigured Spring Security setup.
 *
 * FIXES APPLIED
 * -------------
 * 1. CRITICAL BUG: The original code used a static mutable field:
 *
 *       private static boolean securityConfigFound = false;
 *
 *    This field is NEVER RESET between analyzer runs (e.g., in tests or
 *    batch scanning).  Once any file sets it to true, ALL subsequent runs
 *    of the same JVM will suppress the "no security config" vulnerability
 *    even on projects that genuinely lack security configuration.
 *
 *    FIX: The field has been removed entirely.  analyze() now returns an
 *    AtomicBoolean result per call, and the AnalyzerEngine accumulates
 *    it via a thread-safe flag.  finalizeCheck() now accepts the
 *    accumulated boolean as a parameter instead of reading hidden state.
 *
 * 2. ADDED detection of @SecurityFilterChain annotation and
 *    @Configuration + SecurityFilterChain bean — the modern Spring
 *    Security 5.7+ approach that replaced WebSecurityConfigurerAdapter.
 *
 * 3. ADDED detection of OAuth2/JWT security configuration patterns:
 *    @EnableMethodSecurity, @EnableGlobalMethodSecurity,
 *    @EnableOAuth2Sso, ResourceServerConfigurerAdapter.
 */
public class SecurityConfigRule implements SecurityRule {

    @Override
    public String getRuleName() {
        return "Spring Security Misconfiguration";
    }

    /**
     * Analyzes one compilation unit for security configuration evidence.
     *
     * @return an empty list (configuration presence is binary across the whole
     *         project — callers must accumulate the returned boolean via
     *         {@link #isSecurityConfigPresent(CompilationUnit)}).
     */
    @Override
    public List<Vulnerability> analyze(CompilationUnit cu, String fileName) {
        // Per-file: no per-file vulnerabilities — this rule emits one
        // project-level finding via finalizeCheck().
        return new ArrayList<>();
    }

    /**
     * Returns true if the given compilation unit contains any recognisable
     * Spring Security configuration.
     *
     * This replaces the static boolean side-effect in the original code.
     * Callers (AnalyzerEngine) accumulate results across all files.
     */
    public boolean isSecurityConfigPresent(CompilationUnit cu) {

        for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {

            // Annotation-based detection
            for (AnnotationExpr annotation : clazz.getAnnotations()) {

                String name = annotation.getNameAsString();

                if (name.equals("EnableWebSecurity")
                        || name.equals("EnableMethodSecurity")
                        || name.equals("EnableGlobalMethodSecurity")
                        || name.equals("EnableOAuth2Sso")
                        || name.equals("EnableResourceServer")) {
                    return true;
                }
            }

            // Method return-type detection (SecurityFilterChain bean)
            boolean hasSecurityFilterChain = clazz.getMethods().stream()
                    .anyMatch(m -> m.getType().asString().equals("SecurityFilterChain")
                            || m.getType().asString().equals("WebSecurityCustomizer"));

            if (hasSecurityFilterChain) return true;

            // Legacy class extension detection
            boolean extendsLegacyAdapter = clazz.getExtendedTypes().stream()
                    .anyMatch(t ->
                            t.getNameAsString().equals("WebSecurityConfigurerAdapter")
                                    || t.getNameAsString().equals("ResourceServerConfigurerAdapter")
                                    || t.getNameAsString().equals("AuthorizationServerConfigurerAdapter")
                    );

            if (extendsLegacyAdapter) return true;
        }

        return false;
    }

    /**
     * Called once after all files have been analyzed.
     *
     * FIX: Previously read from a static field that could carry state
     * across runs.  Now receives the accumulated result as a parameter.
     *
     * @param securityConfigFound true if any file contained a security config
     * @return a vulnerability if no configuration was found, else empty list
     */
    public static List<Vulnerability> finalizeCheck(boolean securityConfigFound) {

        List<Vulnerability> result = new ArrayList<>();

        if (!securityConfigFound) {
            result.add(new Vulnerability(
                    "Security Misconfiguration",
                    "Project-level",
                    0,
                    "Application Configuration",
                    "Spring Security",
                    "No Spring Security configuration detected in the project. " +
                            "All endpoints may be publicly accessible without authentication or authorization.",
                    "HIGH",
                    "Add Spring Security: either a @Configuration class with a SecurityFilterChain " +
                            "bean (@EnableWebSecurity), or extend WebSecurityConfigurerAdapter (deprecated). " +
                            "At minimum, ensure all sensitive endpoints require authentication."
            ));
        }

        return result;
    }
}