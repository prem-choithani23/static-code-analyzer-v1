package com.prem_choithani.graph;

public class GraphNode {

    private String label;

    public GraphNode(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}