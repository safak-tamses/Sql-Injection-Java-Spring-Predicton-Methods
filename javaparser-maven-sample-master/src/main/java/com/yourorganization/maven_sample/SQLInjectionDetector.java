package com.yourorganization.maven_sample;

import com.github.javaparser.*;
import com.github.javaparser.ast.*;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SQLInjectionDetector {
    public static void main(String[] args) throws IOException {
        // Klasör yolu
        String folderPath = "C:\\Users\\safak\\Desktop\\BEAM TEKNOLOJİ A.Ş\\website_containing_SQL_injection_vulnerability";

        // Klasördeki tüm Java dosyalarını al
        List<File> javaFiles = getJavaFiles(new File(folderPath));

        // JavaParser nesnesini oluştur
        JavaParser javaParser = new JavaParser();

        // Tüm Java dosyalarını tara ve SQL Injection zafiyeti içeren kodları tespit et
        for (File javaFile : javaFiles) {
            FileInputStream in = new FileInputStream(javaFile);
            ParseResult<CompilationUnit> parseResult = javaParser.parse(in);

            if (parseResult.isSuccessful()) {
                CompilationUnit cu = parseResult.getResult().get();
                cu.accept(new MethodVisitor(javaFile.getPath()), null);
            } else {
                System.err.println("Parsing failed for file: " + javaFile.getName());
            }
        }
    }

    private static List<File> getJavaFiles(File folder) {
        List<File> javaFiles = new ArrayList<>();
        File[] files = folder.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    javaFiles.addAll(getJavaFiles(file));
                } else if (file.isFile() && file.getName().endsWith(".java")) {
                    javaFiles.add(file);
                }
            }
        }

        return javaFiles;
    }
}

class MethodVisitor extends VoidVisitorAdapter<Void> {
    private String filePath;

    public MethodVisitor(String filePath) {
        this.filePath = filePath;
    }

    @Override
    public void visit(MethodDeclaration n, Void arg) {
        super.visit(n, arg);

        // Methodun içeriğini tara
        String methodContent = n.getBody().toString();

        // SQL Injection zafiyeti içeren deseni ara
        if (methodContent.contains("createNativeQuery") && methodContent.contains("entityManager")) {
            System.out.println("Potansiyel SQL Injection zafiyeti tespit edildi:");
            System.out.println("Sınıf: " + n.getParentNode().get().getParentNode().get().getChildNodesByType(ClassOrInterfaceDeclaration.class).get(0).getNameAsString());
            System.out.println("Metod: " + n.getNameAsString());
            System.out.println("Dosya: " + filePath);
            System.out.println("Kod: " + methodContent);
        }
    }
}
