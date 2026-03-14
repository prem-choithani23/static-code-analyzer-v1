package com.prem_choithani.analysis;


import com.prem_choithani.graph.GraphEdge;
import com.prem_choithani.graph.GraphNode;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.stmt.Statement;

import java.util.*;

public class ControlFlowGraphBuilder {

    public Map<GraphNode, List<GraphEdge>> buildCFG(MethodDeclaration method) {

        Map<GraphNode, List<GraphEdge>> graph = new HashMap<>();

        List<Statement> statements = method.findAll(Statement.class);

        GraphNode prev = null;

        for(Statement stmt : statements) {

            GraphNode node = new GraphNode(stmt.toString());

            graph.putIfAbsent(node, new ArrayList<>());

            if(prev != null) {

                graph.get(prev).add(new GraphEdge(prev, node));
            }

            prev = node;
        }

        return graph;
    }
}