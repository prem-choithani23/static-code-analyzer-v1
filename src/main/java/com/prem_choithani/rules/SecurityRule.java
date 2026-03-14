package com.prem_choithani.rules;


import com.github.javaparser.ast.CompilationUnit;
import com.prem_choithani.model.Vulnerability;

import java.util.List;

public interface SecurityRule {

    String getRuleName();

    List<Vulnerability> analyze(
            CompilationUnit cu,
            String fileName
    );

}