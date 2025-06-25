package com.github.avaje.ext;

public class CryptoOperationException extends Exception {

    public CryptoOperationException() {
    }

    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoOperationException(Throwable cause) {
        super(cause);
    }

    public CryptoOperationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
    
}
