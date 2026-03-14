package com.prem_choithani.parser;


import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;

import java.util.ArrayList;
import java.util.List;

public class ASTWalker {

    public List<MethodDeclaration> extractMethods(CompilationUnit cu) {

        List<MethodDeclaration> methods = new ArrayList<>();

        cu.findAll(MethodDeclaration.class)
                .forEach(methods::add);

        return methods;
    }

}