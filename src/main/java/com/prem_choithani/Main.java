package com.prem_choithani;

import com.prem_choithani.core.AnalyzerRunner;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.println("Enter the project path to analyze:");
        String projectPath = sc.nextLine();

        System.out.println("Starting Static Code Analyzer...");
        System.out.println("Target Project: " + projectPath);

        AnalyzerRunner runner = new AnalyzerRunner();
        runner.run(projectPath);

        System.out.println("Analysis completed.");

        sc.close();
    }
}

