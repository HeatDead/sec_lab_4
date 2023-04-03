package com.example.sec_lab_4;

import com.example.sec_lab_4.signature.*;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class DsaApplication extends Application {
    private File file;
    private String fileContent;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private byte[] encryptedMessageBytes;

    private static final String PUBLIC_KEY_FILENAME = "key.pub";
    private static final String PRIVATE_KEY_FILENAME = "_key";

    private DSAKeyPair keyPair;
    private String signa = "";

    @Override
    public void start(Stage stage) throws Exception {
        keyPair = DSAKeyPair.read(new File(PRIVATE_KEY_FILENAME), new File(PUBLIC_KEY_FILENAME));
        stage.setTitle("DSA Signature");
        Text fileLoad = new Text("Выберите файл: ");
        Button loadBtn = new Button("Обзор");
        Text fileLoaded = new Text("Файл не выбран!");

        TextArea textArea = new TextArea();
        textArea.setEditable(false);
        textArea.setMaxSize(300, 100);
        textArea.setWrapText(true);

        Button genKeyBtn = new Button("Generate Signature");
        Text keysGenerated = new Text(" - ");

        Button saveBtn = new Button("Save Signature");
        Text keysSaved = new Text(" - ");

        Button loadOpenKeyBtn = new Button("Load signature");
        Text openKeyLoaded = new Text(" - ");

        Button vrfBtn = new Button("Verify");
        Text vrfText = new Text(" - ");

        FlowPane loadPane = new FlowPane(fileLoad, loadBtn, fileLoaded);
        FlowPane genPane = new FlowPane(genKeyBtn, keysGenerated);
        FlowPane savePane = new FlowPane(saveBtn, keysSaved);
        FlowPane loadOpenPane = new FlowPane(loadOpenKeyBtn, openKeyLoaded);
        FlowPane loadClosePane = new FlowPane(vrfBtn, vrfText);
        FlowPane root = new FlowPane(loadPane, textArea, genPane, savePane,
                loadOpenPane, loadClosePane);
        root.setVgap(5);
        root.setOrientation(Orientation.VERTICAL);

        loadBtn.setOnAction(value -> {
            fileLoadBtnPressed();
            if(file != null) {
                try {
                    fileContent = new Scanner(file).useDelimiter("\\Z").next();
                    fileLoaded.setText("Файл загружен!");
                    textArea.setText(fileContent);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                }
            }
        });

        genKeyBtn.setOnAction(value -> {
            try (InputStream inputStream = new FileInputStream(file)) {
                byte[] sign = new DSASignature().sign(keyPair.getPrivateKey(),
                        inputStream.readAllBytes());
                signa = Base64.getEncoder().encodeToString(sign);
                textArea.setText(Base64.getEncoder().encodeToString(sign));
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });

        saveBtn.setOnAction(value -> {
            try {
                fileSaveBtnPressed();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        loadOpenKeyBtn.setOnAction(value -> {
            try {
                openKeyLoadBtnPressed();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        vrfBtn.setOnAction(value -> {
            System.out.println(signa);
            byte[] signature = Base64.getDecoder().decode(signa.getBytes(StandardCharsets.UTF_8));
            try (InputStream inputStream = new FileInputStream(file)) {
                boolean isVerified = new DSASignature().verify(keyPair.getPublicKey(),
                        inputStream.readAllBytes(),
                        signature);
                vrfText.setText(Boolean.toString(isVerified).toUpperCase());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });



        stage.setScene(new Scene(root, 300, 400));
        stage.setResizable(false);
        stage.centerOnScreen();
        stage.show();
    }

    public void fileLoadBtnPressed() {
        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("Выберите файл (*.*)", "*.*");
        fileChooser.getExtensionFilters().add(fileExtension);
        File file = fileChooser.showOpenDialog(new Stage());
        this.file = file;
    }

    public void fileSaveBtnPressed() throws IOException {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        File selectedDirectory = directoryChooser.showDialog(null);
        String path;
        if (selectedDirectory != null) {
            path = selectedDirectory.getAbsolutePath();
            Files.write( Paths.get(path + "/" + file.getName() + ".sg"), signa.getBytes(StandardCharsets.UTF_8));
        }
    }

    public void openKeyLoadBtnPressed() throws Exception {
        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("Выберите файл (*.sg)", "*.sg");
        fileChooser.getExtensionFilters().add(fileExtension);
        File file = fileChooser.showOpenDialog(new Stage());
        byte[] publicKeyBytes = Files.readAllBytes(file.toPath());
        signa = new Scanner(file).useDelimiter("\\Z").next();
    }

    public void privateKeyLoadBtnPressed() throws Exception {
        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("Выберите файл (*.pk)", "*.pk");
        fileChooser.getExtensionFilters().add(fileExtension);
        File file = fileChooser.showOpenDialog(new Stage());
        byte[] privateKeyBytes = Files.readAllBytes(file.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        privateKey = keyFactory.generatePrivate(privateKeySpec);
    }

    public void message(String message) {
        Stage dialogStage = new Stage();
        dialogStage.initModality(Modality.WINDOW_MODAL);

        VBox vbox = new VBox(new Text(message));
        vbox.setAlignment(Pos.CENTER);
        vbox.setPadding(new Insets(15));

        dialogStage.setScene(new Scene(vbox));
        dialogStage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}