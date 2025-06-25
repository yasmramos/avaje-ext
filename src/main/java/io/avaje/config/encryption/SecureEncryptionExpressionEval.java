package io.avaje.config.encryption;

import com.github.avaje.ext.CryptoOperationException;
import com.github.avaje.ext.SecureEncryptionUtils;
import io.avaje.config.Configuration;

public class SecureEncryptionExpressionEval implements Configuration.ExpressionEval {

    private static final String ENC_PREFIX = "ENC(";
    private static final String ENC_SUFFIX = ")";

    private final Configuration.ExpressionEval delegate;
    private final char[] encryptionPassword;

    public SecureEncryptionExpressionEval(Configuration.ExpressionEval delegate) {
        this.delegate = delegate;
        String password = getEncryptionPassword();
        if (password == null || password.isEmpty()) {
            throw new IllegalStateException("Encryption password required for encrypted properties");
        }
        this.encryptionPassword = password.toCharArray();
    }

    @Override
    public String eval(String expression) {
        String result = delegate.eval(expression);

        if (result != null && result.startsWith(ENC_PREFIX) && result.endsWith(ENC_SUFFIX)) {
            String encryptedValue = result.substring(ENC_PREFIX.length(), result.length() - ENC_SUFFIX.length());
            try {
                return SecureEncryptionUtils.decryptString(encryptedValue, encryptionPassword);
            } catch (CryptoOperationException e) {
                throw new RuntimeException("Failed to decrypt property value: " + e.getMessage(), e);
            }
        }

        return result;
    }

    private String getEncryptionPassword() {
        String password = System.getProperty("config.encryption.password");
        if (password == null) {
            password = System.getenv("CONFIG_ENCRYPTION_PASSWORD");
        }
        return password;
    }
}
