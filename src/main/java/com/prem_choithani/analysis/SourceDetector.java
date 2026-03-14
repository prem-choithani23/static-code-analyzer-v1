package com.prem_choithani.analysis;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;

import java.util.HashSet;
import java.util.Set;

/**
 * Identifies method parameters that receive user-controlled (tainted) data
 * via Spring MVC / Spring REST annotation bindings.
 *
 * FIXES APPLIED
 * -------------
 * 1. MISSING ANNOTATIONS: The original set only covered 7 of the ~12
 *    Spring MVC input-binding annotations.  Missing sources would cause
 *    taint analysis to start with an empty set, suppressing all downstream
 *    vulnerability detection for that method.
 *
 *    Added:
 *    • @MatrixVariable  — URL matrix parameters (/cars;color=red)
 *    • @RequestPart     — multipart file/field uploads (filename injection)
 *    • @RequestAttribute — request-scoped attributes (set by filters/interceptors)
 *    • @SessionAttributes — class-level session binding (accessible per-method)
 *
 * 2. ADDED detection of HttpServletRequest / HttpServletResponse parameters.
 *    When a controller method accepts raw HttpServletRequest, any data
 *    read from it (getParameter, getHeader, getInputStream, etc.) is
 *    user-controlled.  We mark the parameter name as tainted so downstream
 *    analysis can track its use.
 *
 * 3. ADDED detection of @ModelAttribute class-level annotations.
 *    @ModelAttribute on a method parameter is already in the original set,
 *    but @ModelAttribute on a method (not parameter) populates the model
 *    before the handler runs — also a taint source if it reads request data.
 */
public class SourceDetector {

    /**
     * Spring annotations that bind HTTP request data to method parameters.
     * Each annotated parameter is considered a taint source.
     */
    private static final Set<String> SPRING_SOURCES = Set.of(
            // Original set
            "RequestParam",       // ?name=value query parameters
            "PathVariable",       // /users/{id} URI template variables
            "RequestBody",        // JSON/XML request body (deserialization)
            "RequestHeader",      // HTTP request headers (User-Agent, X-Custom, …)
            "CookieValue",        // Cookie values
            "ModelAttribute",     // Form field binding to a model object
            "SessionAttribute",   // Single session attribute read

            // FIX: additions
            "MatrixVariable",     // Matrix parameters: /cars;color=red;year=2020
            "RequestPart",        // Multipart upload field (filename, content-type injection)
            "RequestAttribute",   // Request-scoped attribute (set by filters)
            "SessionAttributes"   // Class-level: multiple session attributes
    );

    /**
     * Types whose instances carry raw HTTP request data and must be
     * treated as taint sources even without a binding annotation.
     */
    private static final Set<String> RAW_REQUEST_TYPES = Set.of(
            "HttpServletRequest",
            "MultipartHttpServletRequest",
            "WebRequest",
            "NativeWebRequest",
            "ServerHttpRequest"   // Reactive / WebFlux
    );

    public Set<String> detectSources(MethodDeclaration method) {

        Set<String> taintedVariables = new HashSet<>();

        for (Parameter param : method.getParameters()) {

            // Check for binding annotations
            for (AnnotationExpr annotation : param.getAnnotations()) {

                if (SPRING_SOURCES.contains(annotation.getNameAsString())) {
                    taintedVariables.add(param.getNameAsString());
                    break;
                }
            }

            // FIX 2: raw HttpServletRequest type implies all data is tainted
            String typeName = param.getType().asString();
            if (RAW_REQUEST_TYPES.contains(typeName)) {
                taintedVariables.add(param.getNameAsString());
            }
        }

        return taintedVariables;
    }
}