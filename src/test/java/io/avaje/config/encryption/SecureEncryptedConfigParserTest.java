import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import io.avaje.config.encryption.SecureEncryptedConfigParser;
import com.github.avaje.ext.EncryptionUtils;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

public class SecureEncryptedConfigParserTest {
    private static final String PASSWORD = "claveSegura123";

    @BeforeAll
    static void setUpPassword() {
        System.setProperty("config.encryption.password", PASSWORD);
    }

    @Test
    void testSupportedExtensions() {
        SecureEncryptedConfigParser parser = new SecureEncryptedConfigParser();
        String[] exts = parser.supportedExtensions();
        assertArrayEquals(new String[]{"enc", "crypt", "safe"}, exts);
    }

    @Test
    void testLoadPlainProperties() {
        SecureEncryptedConfigParser parser = new SecureEncryptedConfigParser();
        StringReader reader = new StringReader("clave=valor\nfoo=bar");
        Map<String, String> map = parser.load(reader);
        // No debe cargar nada porque espera archivo cifrado
        assertTrue(map.isEmpty());
    }

    @Test
    void testLoadEncryptedProperties() throws Exception {
        // Crear archivo de propiedades
        Properties props = new Properties();
        props.setProperty("clave", "valor");
        props.setProperty("foo", "bar");
        Path tempProps = Files.createTempFile("props", ".properties");
        try {
            try (var out = Files.newOutputStream(tempProps)) {
                props.store(out, null);
            }
            // Cifrar el archivo
            Path tempEnc = Files.createTempFile("props", ".enc");
            EncryptionUtils.encryptFile(tempProps.toString(), tempEnc.toString(), PASSWORD.toCharArray());
            // Probar load(InputStream)
            SecureEncryptedConfigParser parser = new SecureEncryptedConfigParser();
            try (var in = Files.newInputStream(tempEnc)) {
                Map<String, String> map = parser.load(in);
                assertEquals("valor", map.get("clave"));
                assertEquals("bar", map.get("foo"));
            }
        } finally {
            Files.deleteIfExists(tempProps);
            // El archivo cifrado se borra en el método
        }
    }
}
