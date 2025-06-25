import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.github.avaje.ext.CryptoOperationException;

public class CryptoOperationExceptionTest {
    @Test
    void testConstructors() {
        CryptoOperationException ex1 = new CryptoOperationException();
        CryptoOperationException ex2 = new CryptoOperationException("mensaje");
        CryptoOperationException ex3 = new CryptoOperationException("mensaje", new Exception("causa"));
        CryptoOperationException ex4 = new CryptoOperationException(new Exception("causa"));
        CryptoOperationException ex5 = new CryptoOperationException("msg", new Exception("c"), true, false);

        assertNull(ex1.getMessage());
        assertEquals("mensaje", ex2.getMessage());
        assertEquals("mensaje", ex3.getMessage());
        assertEquals("causa", ex3.getCause().getMessage());
        assertEquals("causa", ex4.getCause().getMessage());
        assertEquals("msg", ex5.getMessage());
    }
}
