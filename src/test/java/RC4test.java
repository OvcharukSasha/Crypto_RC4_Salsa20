import org.junit.Test;
import rc4.RC4;

import static org.junit.Assert.assertEquals;

public class RC4test {

    @Test
    public void testCryptDecryptMessage() {
        RC4 rc4 = new RC4();
        String message = "Hello, World!";
        String key = "This is pretty long key";
        byte[] crypt = rc4.doEncryption(message.getBytes(), key);
        String msg = rc4.doDecryption(crypt, key);
        assertEquals(message, msg);
    }
}
