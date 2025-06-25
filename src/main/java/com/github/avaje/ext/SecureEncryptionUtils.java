package com.github.avaje.ext;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clase para cifrado seguro de archivos en producción.
 * <p>
 * Características principales:
 * <ul>
 * <li>Cifrado AES-256-GCM con autenticación integrada</li>
 * <li>Derivación de clave PBKDF2 con configuraciones seguras</li>
 * <li>Validación de integridad y autenticidad</li>
 * <li>Protección contra ataques comunes</li>
 * <li>Soporte para metadatos y versionado</li>
 * </ul>
 */
public class SecureEncryptionUtils {

    private static final Logger logger = Logger.getLogger(SecureEncryptionUtils.class.getName());

    // Configuración de algoritmos
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final String SECURE_RANDOM_ALGORITHM = "DRBG";

    // Tamaños recomendados
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_SIZE = 12;
    private static final int GCM_TAG_SIZE = 16;
    private static final int SALT_SIZE = 32;
    private static final int DEFAULT_ITERATIONS = 600_000;

    // Configuración de archivos
    private static final int FILE_FORMAT_VERSION = 3;
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(
            Arrays.asList(
                    ".enc",
                    ".crypt",
                    ".safe",
                    ".sec"
            )
    );
    private static final int MAX_BUFFER_SIZE = 8 * 1024 * 1024;
    private static final int MIN_BUFFER_SIZE = 4 * 1024;

    /**
     * Cifra un archivo con todas las protecciones de producción
     *
     * @param inputPath
     * @param outputPath
     * @param password
     * @throws com.github.avaje.ext.CryptoOperationException
     */
    public static void encryptFile(String inputPath, String outputPath, char[] password)
            throws CryptoOperationException {
        encryptFile(inputPath, outputPath, password, DEFAULT_ITERATIONS, false, MAX_BUFFER_SIZE);
    }

    public static void encryptFile(String inputPath, String outputPath, char[] password,
            int iterations, boolean enableCompression, int bufferSize)
            throws CryptoOperationException {

        validateInputs(inputPath, outputPath, password, iterations, bufferSize);

        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);

        try {
            validateFileOperations(inputFile, outputFile);

            SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
            byte[] salt = new byte[SALT_SIZE];
            secureRandom.nextBytes(salt);
            byte[] iv = new byte[GCM_IV_SIZE];
            secureRandom.nextBytes(iv);

            SecretKey secretKey = deriveEncryptionKey(password, salt, iterations);
            GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_SIZE * 8, iv);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            try (FileInputStream fis = new FileInputStream(inputFile); FileOutputStream fos = new FileOutputStream(outputFile); DataOutputStream headerStream = new DataOutputStream(fos)) {

                writeFileHeader(headerStream, salt, iv, iterations, enableCompression);

                try (CipherOutputStream cos = new CipherOutputStream(fos, cipher); OutputStream output = enableCompression
                        ? new DeflaterOutputStream(cos) : cos) {

                    byte[] buffer = new byte[bufferSize];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        output.write(buffer, 0, bytesRead);
                    }
                }
            }

            logger.log(Level.INFO, "Cifrado completado exitosamente. Archivo: {0}", outputPath);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoOperationException("Error de configuración criptográfica", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoOperationException("Parámetros criptográficos inválidos", e);
        } catch (IOException e) {
            throw new CryptoOperationException("Error de E/S durante el cifrado", e);
        } catch (InvalidKeySpecException e) {
            throw new CryptoOperationException("Error en especificación de clave", e);
        } finally {
            //Arrays.fill(password, '\0');
        }
    }

    public static void decryptFile(String inputPath, String outputPath, char[] password)
            throws CryptoOperationException {

        if (inputPath == null || outputPath == null || password == null) {
            throw new CryptoOperationException("Parámetros no pueden ser nulos");
        }

        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);

        try {
            validateFileOperations(inputFile, outputFile);

            try (FileInputStream fis = new FileInputStream(inputFile); DataInputStream headerStream = new DataInputStream(fis)) {

                FileHeader header = readFileHeader(headerStream);

                if (header.version > FILE_FORMAT_VERSION) {
                    throw new CryptoOperationException(
                            "Versión de formato no soportada: " + header.version);
                }

                SecretKey secretKey = deriveEncryptionKey(password, header.salt, header.iterations);
                GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_SIZE * 8, header.iv);
                Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                try (CipherInputStream cis = new CipherInputStream(fis, cipher); InputStream input = header.compressed
                        ? new InflaterInputStream(cis) : cis; FileOutputStream fos = new FileOutputStream(outputFile)) {

                    byte[] buffer = new byte[MAX_BUFFER_SIZE];
                    int bytesRead;
                    while ((bytesRead = input.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                }
            }

            logger.log(Level.INFO, "Descifrado completado exitosamente. Archivo: {0}", outputPath);
        } catch (IOException e) {
            throw new CryptoOperationException("Error de E/S durante descifrado: " + e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new CryptoOperationException("Error de seguridad durante descifrado: " + e.getMessage(), e);
        } finally {
            //Arrays.fill(password, '\0');
        }
    }

    // Métodos auxiliares
    private static SecretKey deriveEncryptionKey(char[] password, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password, salt, iterations, AES_KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static void writeFileHeader(DataOutputStream dos, byte[] salt, byte[] iv,
            int iterations, boolean compressed) throws IOException {
        dos.writeInt(FILE_FORMAT_VERSION);
        dos.writeInt(iterations);
        dos.writeInt(compressed ? 1 : 0);
        dos.writeInt(salt.length);
        dos.write(salt);
        dos.writeInt(iv.length);
        dos.write(iv);
    }

    private static FileHeader readFileHeader(DataInputStream dis) throws IOException {
        FileHeader header = new FileHeader();
        header.version = dis.readInt();
        header.iterations = dis.readInt();
        header.compressed = dis.readInt() == 1;

        header.salt = new byte[dis.readInt()];
        dis.readFully(header.salt);

        header.iv = new byte[dis.readInt()];
        dis.readFully(header.iv);

        return header;
    }

    /**
     * Verifica si un archivo está cifrado con nuestro formato
     *
     * @param filePath Ruta del archivo a verificar
     * @return true si el archivo parece estar cifrado con nuestro formato,
     * false en caso contrario
     * @throws IOException Si ocurre un error al leer el archivo
     */
    public static boolean isEncryptedFile(String filePath) throws IOException {
        File file = new File(filePath);

        // Verificaciones básicas
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            return false;
        }

        // El archivo debe tener al menos el tamaño mínimo de la cabecera
        long minSize = SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE;
        if (file.length() < minSize) {
            return false;
        }

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            // Leer versión del formato
            int version = raf.readInt();

            // Verificar versión compatible
            if (version < 1 || version > FILE_FORMAT_VERSION) {
                return false;
            }

            // Leer el resto de la cabecera para verificar estructura
            raf.readInt(); // iteraciones
            raf.readInt(); // flag de compresión

            // Leer tamaños de salt e IV
            int saltLength = raf.readInt();
            byte[] salt = new byte[saltLength];
            raf.readFully(salt);

            int ivLength = raf.readInt();
            byte[] iv = new byte[ivLength];
            raf.readFully(iv);

            // Verificar tamaños esperados
            return saltLength == SALT_SIZE && ivLength == GCM_IV_SIZE;

        } catch (Exception e) {
            // Cualquier error de lectura o formato indica que no es un archivo cifrado válido
            return false;
        }
    }

    private static class FileHeader {

        int version;
        int iterations;
        boolean compressed;
        byte[] salt;
        byte[] iv;
    }

    private static void validateInputs(String inputPath, String outputPath,
            char[] password, int iterations, int bufferSize)
            throws CryptoOperationException {

        if (inputPath == null || outputPath == null || password == null) {
            throw new CryptoOperationException("Parámetros no pueden ser nulos");
        }

        if (password.length == 0) {
            throw new CryptoOperationException("La contraseña no puede estar vacía");
        }

        if (iterations < 100_000) {
            throw new CryptoOperationException("Iteraciones deben ser al menos 100,000");
        }

        if (bufferSize < MIN_BUFFER_SIZE || bufferSize > MAX_BUFFER_SIZE) {
            throw new CryptoOperationException(
                    String.format("Tamaño de buffer debe estar entre %d y %d bytes",
                            MIN_BUFFER_SIZE, MAX_BUFFER_SIZE));
        }

        String outputLower = outputPath.toLowerCase();
        String ext = outputLower.substring(outputLower.lastIndexOf('.'));
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new CryptoOperationException(
                    "Archivos cifrados deben tener una extensión permitida: " + String.join(", ", ALLOWED_EXTENSIONS));
        }
    }

    private static void validateFileOperations(File inputFile, File outputFile)
            throws CryptoOperationException, FileNotFoundException {

        if (!inputFile.exists()) {
            throw new FileNotFoundException("Archivo de entrada no existe: " + inputFile.getPath());
        }

        if (!inputFile.canRead()) {
            throw new CryptoOperationException("No se puede leer el archivo de entrada: " + inputFile.getPath());
        }

        if (outputFile.exists() && !outputFile.canWrite()) {
            throw new CryptoOperationException("No se puede escribir en el archivo de salida: " + outputFile.getPath());
        }

        if (inputFile.getAbsolutePath().equals(outputFile.getAbsolutePath())) {
            throw new CryptoOperationException("Archivo de entrada y salida no pueden ser el mismo");
        }
    }

    /**
     * Cifra un String y lo devuelve como Base64
     *
     * @param plainText Texto a cifrar
     * @param password Contraseña para derivar la clave
     * @return String cifrado en Base64
     * @throws com.github.avaje.ext.CryptoOperationException
     */
    public static String encryptString(String plainText, char[] password) throws CryptoOperationException {
        try {
            // Generar componentes criptográficos
            SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
            byte[] salt = new byte[SALT_SIZE];
            secureRandom.nextBytes(salt);
            byte[] iv = new byte[GCM_IV_SIZE];
            secureRandom.nextBytes(iv);

            // Derivar clave
            SecretKey secretKey = deriveEncryptionKey(password, salt, DEFAULT_ITERATIONS);

            // Configurar cifrado
            GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_SIZE * 8, iv);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            // Cifrar datos
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Combinar salt + iv + datos cifrados
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(salt);
            outputStream.write(iv);
            outputStream.write(encryptedBytes);

            // Convertir a Base64 para fácil manejo como String
            return Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw new CryptoOperationException("Error al cifrar string", e);
        } finally {
            //Arrays.fill(password, '\0');
        }
    }

    /**
     * Descifra un String previamente cifrado con encryptString
     *
     * @param encryptedText Texto cifrado en Base64
     * @param password Contraseña usada para cifrar
     * @return String descifrado
     * @throws com.github.avaje.ext.CryptoOperationException
     */
    public static String decryptString(String encryptedText, char[] password) throws CryptoOperationException {
        try {
            // Decodificar Base64
            byte[] combined = Base64.getDecoder().decode(encryptedText);

            // Extraer componentes
            ByteArrayInputStream inputStream = new ByteArrayInputStream(combined);
            byte[] salt = new byte[SALT_SIZE];
            inputStream.read(salt);
            byte[] iv = new byte[GCM_IV_SIZE];
            inputStream.read(iv);
            byte[] encryptedData = inputStream.readAllBytes();

            // Derivar clave
            SecretKey secretKey = deriveEncryptionKey(password, salt, DEFAULT_ITERATIONS);

            // Configurar descifrado
            GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_SIZE * 8, iv);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            // Descifrar datos
            byte[] decryptedBytes = cipher.doFinal(encryptedData);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new CryptoOperationException("Autenticación fallida - texto corrupto o contraseña incorrecta", e);
        } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw new CryptoOperationException("Error al descifrar string", e);
        } finally {
           // Arrays.fill(password, '\0');
        }
    }

}
