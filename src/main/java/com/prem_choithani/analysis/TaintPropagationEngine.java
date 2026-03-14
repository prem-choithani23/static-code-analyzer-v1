package com.prem_choithani.analysis;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.body.VariableDeclarator;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public class TaintPropagationEngine {

    public Set<String> propagateTaint(MethodDeclaration method, Set<String> sources) {

        Set<String> tainted = new HashSet<>(sources);

        boolean changed = true;

        while (changed) {

            changed = false;

            changed |= propagateAssignments(method, tainted);
            changed |= propagateDeclarations(method, tainted);

        }

        return tainted;
    }

    private boolean propagateAssignments(MethodDeclaration method, Set<String> tainted) {

        boolean changed = false;

        for (AssignExpr assign : method.findAll(AssignExpr.class)) {

            Expression value = assign.getValue();

            for (NameExpr name : value.findAll(NameExpr.class)) {

                if (tainted.contains(name.getNameAsString())) {

                    String target = assign.getTarget().toString();

                    if (!tainted.contains(target)) {

                        tainted.add(target);
                        changed = true;

                    }

                }

            }

        }

        return changed;
    }

    private boolean propagateDeclarations(MethodDeclaration method, Set<String> tainted) {

        AtomicBoolean changed = new AtomicBoolean(false);

        for (VariableDeclarationExpr decl : method.findAll(VariableDeclarationExpr.class)) {

            for (VariableDeclarator var : decl.getVariables()) {

                var.getInitializer().ifPresent(init -> {

                    for (NameExpr name : init.findAll(NameExpr.class)) {

                        if (tainted.contains(name.getNameAsString())) {

                            if (!tainted.contains(var.getNameAsString())) {

                                tainted.add(var.getNameAsString());
                                changed.set(true);

                            }

                        }

                    }

                });

            }

        }

        return changed.get();
    }
}