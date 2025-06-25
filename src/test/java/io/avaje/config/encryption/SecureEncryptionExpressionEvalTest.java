import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import io.avaje.config.encryption.SecureEncryptionExpressionEval;
import io.avaje.config.Configuration;
import com.github.avaje.ext.SecureEncryptionUtils;

public class SecureEncryptionExpressionEvalTest {
    private static final String PASSWORD = "claveSegura123";

    static class DummyEval implements Configuration.ExpressionEval {
        private final String value;
        DummyEval(String value) { this.value = value; }
        @Override public String eval(String expression) { return value; }
    }

    @BeforeAll
    static void setUpPassword() {
        System.setProperty("config.encryption.password", PASSWORD);
    }

    @Test
    void testEvalEncrypted() throws Exception {
        String texto = "valorSecreto";
        String encrypted = SecureEncryptionUtils.encryptString(texto, PASSWORD.toCharArray());
        String expr = "ENC(" + encrypted + ")";
        SecureEncryptionExpressionEval eval = new SecureEncryptionExpressionEval(new DummyEval(expr));
        String result = eval.eval("");
        assertEquals(texto, result);
    }

    @Test
    void testEvalPlain() {
        SecureEncryptionExpressionEval eval = new SecureEncryptionExpressionEval(new DummyEval("simple"));
        assertEquals("simple", eval.eval(""));
    }
}
