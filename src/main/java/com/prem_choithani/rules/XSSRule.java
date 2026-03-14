package com.prem_choithani.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NameExpr;

import com.prem_choithani.analysis.SourceDetector;
import com.prem_choithani.analysis.SinkDetector;
import com.prem_choithani.analysis.TaintPropagationEngine;
import com.prem_choithani.model.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class XSSRule implements SecurityRule {

    private final SourceDetector sourceDetector = new SourceDetector();
    private final SinkDetector sinkDetector = new SinkDetector();
    private final TaintPropagationEngine taintEngine = new TaintPropagationEngine();

    @Override
    public String getRuleName() {
        return "Cross Site Scripting (XSS)";
    }

    @Override
    public List<Vulnerability> analyze(CompilationUnit cu, String fileName) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {

            Set<String> sources = sourceDetector.detectSources(method);

            if (sources.isEmpty()) continue;

            Set<String> tainted = taintEngine.propagateTaint(method, sources);

            List<Expression> sinks = sinkDetector.detectSinks(method);

            for (Expression sink : sinks) {

                boolean taintedFlow = false;

                for (NameExpr name : sink.findAll(NameExpr.class)) {

                    if (tainted.contains(name.getNameAsString())) {

                        taintedFlow = true;
                        break;

                    }

                }

                if (taintedFlow) {

                    int line = sink.getBegin()
                            .map(p -> p.line)
                            .orElse(-1);

                    vulnerabilities.add(
                            new Vulnerability(
                                    "XSS",
                                    fileName,
                                    line,
                                    sources.toString(),
                                    sink.toString(),
                                    "User-controlled input flows into HTML output",
                                    "HIGH",
                                    "Escape output using HtmlUtils.htmlEscape() or OWASP Encoder"
                            )
                    );

                }

            }

        }

        return vulnerabilities;
    }
}