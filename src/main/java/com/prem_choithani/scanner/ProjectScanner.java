package com.prem_choithani.scanner;

import java.util.List;
import java.io.File;

public class ProjectScanner {

    private final FileCollector fileCollector;

    public ProjectScanner() {
        this.fileCollector = new FileCollector();
    }

    public List<File> scanProject(String projectRootPath) {

        File root = new File(projectRootPath);

        if (!root.exists()) {
            throw new RuntimeException("Project path does not exist: " + projectRootPath);
        }

        System.out.println("Scanning project directory: " + projectRootPath);

        List<File> javaFiles = fileCollector.collectJavaFiles(root);

        System.out.println("Total Java files discovered: " + javaFiles.size());

        return javaFiles;
    }
}