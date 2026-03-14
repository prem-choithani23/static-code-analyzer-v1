package com.prem_choithani.model;


public class Endpoint {

    private String httpMethod;
    private String path;
    private String controllerClass;
    private String methodName;

    public Endpoint(String httpMethod, String path, String controllerClass, String methodName) {
        this.httpMethod = httpMethod;
        this.path = path;
        this.controllerClass = controllerClass;
        this.methodName = methodName;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getPath() {
        return path;
    }

    public String getControllerClass() {
        return controllerClass;
    }

    public String getMethodName() {
        return methodName;
    }

    @Override
    public String toString() {
        return httpMethod + " " + path + " -> " + controllerClass + "." + methodName;
    }
}