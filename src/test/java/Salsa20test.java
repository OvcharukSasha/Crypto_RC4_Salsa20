
import org.junit.jupiter.api.Test;
import salsa20.Salsa20;

import static org.junit.Assert.assertArrayEquals;


public class Salsa20test {

    public static int SYM_IV_SIZE = 8;
    public static int SYM_KEY_SIZE = 16;

    @Test
    public void salsa20EncryptDecryptTest() {
        byte[] iv = new byte[SYM_IV_SIZE];
        byte[] key = new byte[SYM_KEY_SIZE];
        Salsa20 salsa20Encrypter = new Salsa20();
        Salsa20 salsa20Decrypter = new Salsa20();
        salsa20Encrypter.init(key, iv);
        salsa20Decrypter.init(key, iv);
        byte[] msg = "Message to crypt".getBytes();
        byte[] cMsg;
        byte[] eMsg;
        cMsg = salsa20Encrypter.crypt(msg, 0, msg.length);
        eMsg = salsa20Decrypter.crypt(cMsg, 0, cMsg.length);
        assertArrayEquals(msg, eMsg);
    }


}