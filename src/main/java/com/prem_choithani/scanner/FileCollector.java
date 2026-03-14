package com.prem_choithani.scanner;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class FileCollector {

    public List<File> collectJavaFiles(File directory) {

        List<File> javaFiles = new ArrayList<>();

        if (directory == null || !directory.exists()) {
            return javaFiles;
        }

        File[] files = directory.listFiles();

        if (files == null) {
            return javaFiles;
        }

        for (File file : files) {

            if (file.isDirectory()) {

                javaFiles.addAll(collectJavaFiles(file));

            } else if (file.getName().endsWith(".java")) {

                javaFiles.add(file);

            }
        }

        return javaFiles;
    }
}