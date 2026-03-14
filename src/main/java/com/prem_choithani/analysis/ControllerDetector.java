package com.prem_choithani.analysis;

import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.prem_choithani.model.Endpoint;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Detects Spring MVC / Spring REST controller classes and extracts
 * their declared HTTP endpoints.
 *
 * FIXES APPLIED
 * -------------
 * 1. MISSING HTTP METHOD: @PatchMapping was not handled.
 *    PATCH is widely used in REST APIs for partial updates and is equally
 *    subject to injection attacks as POST/PUT.
 *    FIX: Added "PatchMapping" to the recognized annotation set.
 *
 * 2. PATH EXTRACTION: annotation.toString() returned the raw annotation
 *    source text (e.g. '@GetMapping("/users/{id}")'), not just the path.
 *    FIX: Replaced with extractPath(annotation) which parses the annotation
 *    member values to extract the actual path string.
 *
 * 3. ADDED class-level @RequestMapping prefix support.
 *    A @RequestMapping("/api") on the class is prepended to each method
 *    path to give a fully-qualified endpoint path in the report.
 *
 * 4. ADDED recognition of @RepositoryRestController (Spring Data REST)
 *    and @RestControllerAdvice (used for exception handlers that can also
 *    have security relevance).
 */
public class ControllerDetector {

    // FIX 1: PatchMapping added; FIX 4: RepositoryRestController added
    private static final Set<String> CONTROLLER_ANNOTATIONS = Set.of(
            "RestController",
            "Controller",
            "RepositoryRestController",
            "RestControllerAdvice"
    );

    // FIX 1: PatchMapping added to the mapping set
    private static final Set<String> MAPPING_ANNOTATIONS = Set.of(
            "GetMapping",
            "PostMapping",
            "PutMapping",
            "DeleteMapping",
            "PatchMapping",       // FIX: was missing
            "RequestMapping"
    );

    public List<Endpoint> detectControllers(CompilationUnit cu) {

        List<Endpoint> endpoints = new ArrayList<>();

        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(clazz -> {

            boolean isController = clazz.getAnnotations().stream()
                    .map(AnnotationExpr::getNameAsString)
                    .anyMatch(CONTROLLER_ANNOTATIONS::contains);

            if (!isController) return;

            // FIX 3: extract class-level base path
            String classBasePath = extractClassBasePath(clazz);
            String className = clazz.getNameAsString();

            clazz.getMethods().forEach(method -> {

                method.getAnnotations().forEach(annotation -> {

                    String name = annotation.getNameAsString();

                    if (!MAPPING_ANNOTATIONS.contains(name)) return;

                    // FIX 2: extract the actual path string, not toString()
                    String methodPath = extractPath(annotation);

                    // FIX 3: prepend class-level base path
                    String fullPath = classBasePath.isEmpty()
                            ? methodPath
                            : classBasePath + (methodPath.startsWith("/") ? methodPath : "/" + methodPath);

                    // Derive HTTP verb
                    String httpMethod = name.equals("RequestMapping")
                            ? extractRequestMappingMethod(annotation)
                            : name.replace("Mapping", "").toUpperCase();

                    endpoints.add(new Endpoint(
                            httpMethod,
                            fullPath,
                            className,
                            method.getNameAsString()
                    ));
                });
            });
        });

        return endpoints;
    }

    // ---------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------

    /**
     * Extracts the path value from a mapping annotation.
     *
     * Handles:
     *   @GetMapping("/users")          → "/users"
     *   @GetMapping(value = "/users")  → "/users"
     *   @GetMapping(path = "/users")   → "/users"
     *   @GetMapping                    → ""   (root path)
     */
    private String extractPath(AnnotationExpr annotation) {

        // Single-value annotation: @GetMapping("/path")
        if (annotation.isSingleMemberAnnotationExpr()) {
            return annotation.asSingleMemberAnnotationExpr()
                    .getMemberValue()
                    .findFirst(StringLiteralExpr.class)
                    .map(StringLiteralExpr::asString)
                    .orElse("");
        }

        // Normal annotation: @RequestMapping(value = "/path") or path = …
        if (annotation.isNormalAnnotationExpr()) {
            return annotation.asNormalAnnotationExpr().getPairs().stream()
                    .filter(pair -> {
                        String key = pair.getNameAsString();
                        return key.equals("value") || key.equals("path");
                    })
                    .findFirst()
                    .flatMap(pair -> pair.getValue()
                            .findFirst(StringLiteralExpr.class))
                    .map(StringLiteralExpr::asString)
                    .orElse("");
        }

        // Marker annotation: @GetMapping (no arguments — root handler)
        return "";
    }

    /**
     * Extracts the HTTP method from @RequestMapping(method = RequestMethod.POST).
     * Defaults to "ALL" if method attribute is absent (matches all methods).
     */
    private String extractRequestMappingMethod(AnnotationExpr annotation) {

        if (annotation.isNormalAnnotationExpr()) {
            return annotation.asNormalAnnotationExpr().getPairs().stream()
                    .filter(pair -> pair.getNameAsString().equals("method"))
                    .findFirst()
                    .map(MemberValuePair::getValue)
                    .map(v -> v.toString()
                            .replace("RequestMethod.", "")
                            .replace("{", "").replace("}", "").trim())
                    .orElse("ALL");
        }

        return "ALL";
    }

    /** Returns the class-level base path, or empty string if none. */
    private String extractClassBasePath(ClassOrInterfaceDeclaration clazz) {

        return clazz.getAnnotations().stream()
                .filter(a -> a.getNameAsString().equals("RequestMapping"))
                .findFirst()
                .map(this::extractPath)
                .orElse("");
    }
}