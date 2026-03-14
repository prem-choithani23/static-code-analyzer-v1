package com.prem_choithani.cli;

import com.prem_choithani.core.AnalyzerRunner;

import java.io.File;


public class CLIApplication {

    public static void main(String[] args) {

        if (args.length == 0) {

            System.out.println("Usage: java -jar analyzer.jar <project-path>");
            return;

        }

        String projectPath = args[0];

        AnalyzerRunner runner = new AnalyzerRunner();

        runner.run(projectPath);

    }

}