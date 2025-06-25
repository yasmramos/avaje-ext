import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.github.avaje.ext.SecureEncryptionUtils;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class SecureEncryptionUtilsTest {

    private static final char[] PASSWORD = "claveSegura123".toCharArray();

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        String original = "textoSecreto";
        String encrypted = SecureEncryptionUtils.encryptString(original, PASSWORD);
        assertNotNull(encrypted);
        assertNotEquals(original, encrypted);

        String decrypted = SecureEncryptionUtils.decryptString(encrypted, PASSWORD);
        assertEquals(original, decrypted);
    }

    @Test
    public void testEncryptNull() {
        assertThrows(Exception.class, () -> {
            SecureEncryptionUtils.encryptString(null, PASSWORD);
        });
    }

    @Test
    public void testDecryptNull() {
        assertThrows(Exception.class, () -> {
            SecureEncryptionUtils.decryptString(null, PASSWORD);
        });
    }

    @Test
    public void testDecryptWithWrongPassword() throws Exception {
        String original = "textoSecreto";
        String encrypted = SecureEncryptionUtils.encryptString(original, PASSWORD);
        char[] wrongPassword = "otraClave".toCharArray();
        assertThrows(Exception.class, () -> {
            SecureEncryptionUtils.decryptString(encrypted, wrongPassword);
        });
    }

    @Test
    public void testEncryptAndDecryptFile() throws Exception {
        String originalContent = "contenido de prueba para archivo";
        Path tempInput = Files.createTempFile("testInput", ".txt");
        Path tempEncrypted = Files.createTempFile("testEncrypted", ".enc");
        Path tempDecrypted = Files.createTempFile("testDecrypted", ".txt");
        try {
            Files.write(tempInput, originalContent.getBytes(StandardCharsets.UTF_8));
            SecureEncryptionUtils.encryptFile(tempInput.toString(), tempEncrypted.toString(), PASSWORD);
            assertTrue(Files.size(tempEncrypted) > 0);
            SecureEncryptionUtils.decryptFile(tempEncrypted.toString(), tempDecrypted.toString(), PASSWORD);
            String decryptedContent = Files.readString(tempDecrypted, StandardCharsets.UTF_8);
            assertEquals(originalContent, decryptedContent);
        } finally {
            Files.deleteIfExists(tempInput);
            Files.deleteIfExists(tempEncrypted);
            Files.deleteIfExists(tempDecrypted);
        }
    }
}