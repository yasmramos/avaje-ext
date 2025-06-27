package com.github.avaje.ext;

import io.avaje.config.Config;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Stream;

public class EncConfig {

    /**
     * Establece una propiedad cifrada en la configuración.
     */
    public static void setEncryptedProperty(String key, String value) {
        try {
            Config.setProperty(key, "ENC(" + EncryptionUtils.encryptString(value, getPassword()) + ")");
        } catch (CryptoOperationException ex) {
            logError(ex);
        }
    }

    /**
     * Guarda las propiedades en un archivo cifrado y elimina el archivo
     * original.
     */
    public static void saveEncryptedProperties(String inputfileName, String outputfileName) {
        saveEncryptedProperties(inputfileName, outputfileName, true);
    }

    /**
     * Guarda las propiedades en un archivo cifrado. Puede eliminar el archivo
     * original si se indica.
     */
    public static void saveEncryptedProperties(String inputfileName, String outputfileName, boolean deleteInput) {
        try {
            savePropertiesToFile(inputfileName);
            EncryptionUtils.encryptFile(inputfileName, outputfileName, getPassword());
            if (deleteInput) {
                Files.deleteIfExists(Path.of(inputfileName));
            }
        } catch (IOException | CryptoOperationException ex) {
            logError(ex);
        }
    }

    /**
     * Guarda las propiedades en un archivo normal y elimina archivos cifrados
     * si se indica.
     */
    public static void savePlainProperties(String inputfileName, boolean deleteEncFiles) {
        try {
            savePropertiesToFile(inputfileName);
            if (deleteEncFiles) {
                Set<String> allowedExtensions = EncryptionUtils.getALLOWED_EXTENSIONS();
                for (String ext : allowedExtensions) {
                    try (Stream<Path> list = Files.list(Path.of("."))) {
                        list.filter(f -> f.toString().endsWith(ext))
                                .forEach(f -> {
                                    try {
                                        Files.deleteIfExists(f);
                                    } catch (IOException ignored) {
                                    }
                                });
                    }
                }
            }
        } catch (IOException ex) {
            logError(ex);
        }
    }

    private static char[] getPassword() {
        String pwd = System.getProperty("config.encryption.password");
        if (pwd == null) {
            throw new IllegalStateException("config.encryption.password no definida");
        }
        return pwd.toCharArray();
    }

    private static void savePropertiesToFile(String fileName) throws IOException {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            Config.asProperties().store(out, null);
        }
    }

    private static void logError(Exception ex) {
        System.getLogger(EncConfig.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
    }
}
