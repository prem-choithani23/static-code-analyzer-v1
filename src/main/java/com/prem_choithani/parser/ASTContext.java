package com.prem_choithani.parser;

import com.github.javaparser.ast.CompilationUnit;
import java.io.File;

public class ASTContext {

    private final File file;
    private final CompilationUnit compilationUnit;

    public ASTContext(File file, CompilationUnit compilationUnit) {
        this.file = file;
        this.compilationUnit = compilationUnit;
    }

    public File getFile() {
        return file;
    }

    public String getFileName() {
        return file.getName();
    }

    public CompilationUnit getCompilationUnit() {
        return compilationUnit;
    }

}