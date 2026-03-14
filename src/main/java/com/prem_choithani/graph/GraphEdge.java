package com.prem_choithani.graph;


public class GraphEdge {

    private GraphNode from;
    private GraphNode to;

    public GraphEdge(GraphNode from, GraphNode to) {
        this.from = from;
        this.to = to;
    }

    public GraphNode getFrom() {
        return from;
    }

    public GraphNode getTo() {
        return to;
    }
}