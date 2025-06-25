package io.avaje.config.encryption;

import com.github.avaje.ext.CryptoOperationException;
import com.github.avaje.ext.SecureEncryptionUtils;
import io.avaje.config.ConfigParser;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public final class SecureEncryptedConfigParser implements ConfigParser {

    private static final String[] extensions = {"enc", "crypt", "safe"};
    private final char[] encryptionPassword;

    public SecureEncryptedConfigParser() {
        String password = getEncryptionPassword();
        if (password == null || password.isEmpty()) {
            throw new IllegalStateException("Encryption password required. Set CONFIG_ENCRYPTION_PASSWORD environment variable or config.encryption.password system property");
        }
        this.encryptionPassword = password.toCharArray();
    }

    @Override
    public String[] supportedExtensions() {
        return extensions.clone();
    }

    @Override
    public Map<String, String> load(Reader reader) {
        try {
            // Para Reader, necesitamos convertir a archivo temporal  
            String tempContent = readAll(reader);
            Path tempFile = Files.createTempFile("config-encrypted", ".tmp");
            try {
                Files.writeString(tempFile, tempContent);
                return loadFromFile(tempFile.toString());
            } finally {
                Files.deleteIfExists(tempFile);
            }
        } catch (IOException iOException) {
            iOException.printStackTrace();
        }
        return Map.of();
    }

    @Override
    public Map<String, String> load(InputStream inputStream) {
        try {
            // Convertir InputStream a archivo temporal  
            Path tempFile = Files.createTempFile("config-encrypted", ".tmp");
            try {
                Files.copy(inputStream, tempFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                return loadFromFile(tempFile.toString());
            } finally {
                Files.deleteIfExists(tempFile);
            }
        } catch (IOException iOException) {
            iOException.printStackTrace();
        }
        return Map.of();
    }

    private Map<String, String> loadFromFile(String filePath) throws IOException {
        // Verificar si el archivo está encriptado
        if (!SecureEncryptionUtils.isEncryptedFile(filePath)) {
            throw new IOException("File is not encrypted with the expected format: " + filePath);
        }
        // Crear archivo temporal para el contenido desencriptado
        Path decryptedFile = Files.createTempFile("config-decrypted", ".properties");
        try {
            // Desencriptar archivo
            SecureEncryptionUtils.decryptFile(filePath, decryptedFile.toString(), encryptionPassword);

            // Cargar propiedades del archivo desencriptado
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(decryptedFile.toFile())) {
                props.load(fis);
            }

            return propertiesToMap(props);
        } catch (CryptoOperationException ex) {
            System.getLogger(SecureEncryptedConfigParser.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } finally {
            Files.deleteIfExists(decryptedFile);
        }
        return Map.of();
    }

    private String getEncryptionPassword() {
        String password = System.getProperty("config.encryption.password");
        if (password == null) {
            password = System.getenv("CONFIG_ENCRYPTION_PASSWORD");
        }
        return password;
    }

    private String readAll(Reader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        char[] buffer = new char[8192];
        int length;
        while ((length = reader.read(buffer)) != -1) {
            sb.append(buffer, 0, length);
        }
        return sb.toString();
    }

    private Map<String, String> propertiesToMap(Properties props) {
        Map<String, String> map = new HashMap<>();
        for (String key : props.stringPropertyNames()) {
            map.put(key, props.getProperty(key));
        }
        return map;
    }
}
