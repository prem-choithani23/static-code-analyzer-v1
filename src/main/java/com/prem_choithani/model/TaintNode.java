package com.prem_choithani.model;


public class TaintNode {

    private String variableName;
    private boolean tainted;
    private int line;

    public TaintNode(String variableName, boolean tainted, int line) {
        this.variableName = variableName;
        this.tainted = tainted;
        this.line = line;
    }

    public String getVariableName() {
        return variableName;
    }

    public boolean isTainted() {
        return tainted;
    }

    public void setTainted(boolean tainted) {
        this.tainted = tainted;
    }

    public int getLine() {
        return line;
    }

}