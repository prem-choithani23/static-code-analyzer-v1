package com.prem_choithani.parser;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Parses a Java source file into a JavaParser CompilationUnit (AST).
 *
 * FIXES APPLIED
 * -------------
 * 1. RESOURCE LEAK: The original code opened a FileInputStream and called
 *    fis.close() manually after parse:
 *
 *       FileInputStream fis = new FileInputStream(javaFile);
 *       CompilationUnit cu = StaticJavaParser.parse(fis);
 *       fis.close();     ← never reached if parse() throws
 *
 *    If StaticJavaParser.parse() throws any exception, fis.close() is
 *    skipped, leaving the file handle open until GC.  In a large project
 *    scan this causes "Too many open files" OS errors.
 *
 *    FIX: Replaced with try-with-resources, which guarantees close() is
 *    called even when an exception is thrown.
 *
 * 2. Exception message now includes the absolute path (more useful than
 *    just the relative name when diagnosing failures in deep directories).
 */
public class ASTBuilder {

    public CompilationUnit build(File javaFile) {

        // FIX: try-with-resources ensures FileInputStream is always closed
        try (FileInputStream fis = new FileInputStream(javaFile)) {

            return StaticJavaParser.parse(fis);

        } catch (IOException e) {
            throw new RuntimeException(
                    "AST parsing failed for file: " + javaFile.getAbsolutePath(), e);
        }
    }
}