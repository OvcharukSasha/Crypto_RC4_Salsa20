package rc4;

import java.util.Arrays;

public class RC4 {
    private static final int SBOX_SIZE = 256;
    private static final int KEY_MIN_SIZE = 5;
    private byte[] key = new byte[SBOX_SIZE - 1];

    private int[] sbox = new int[SBOX_SIZE];

    public RC4() {
        resetByDefault();
    }

    private void resetByDefault() {
        Arrays.fill(key, (byte) 0);
        Arrays.fill(sbox, 0);
    }

    public byte[] doEncryption(byte[] message, String key) {
        resetByDefault();
        setKey(key);
        byte[] crypt = crypt(message);
        resetByDefault();
        return crypt;
    }

    public String doDecryption(byte[] message, String key) {
        resetByDefault();
        setKey(key);
        byte[] msg = crypt(message);
        resetByDefault();
        return new String(msg);
    }

    public byte[] crypt(final byte[] msg) {
        sbox = initSBox(key);
        byte[] code = new byte[msg.length];
        int i = 0;
        int j = 0;
        for (int n = 0; n < msg.length; n++) {
            i = (i + 1) % SBOX_SIZE;
            j = (j + sbox[i]) % SBOX_SIZE;
            swap(i, j, sbox);
            int rand = sbox[(sbox[i] + sbox[j]) % SBOX_SIZE];
            code[n] = (byte) (rand ^ msg[n]);
        }
        return code;
    }

    private int[] initSBox(byte[] key) {
        int[] sbox = new int[SBOX_SIZE];
        int j = 0;

        for (int i = 0; i < SBOX_SIZE; i++) {
            sbox[i] = i;
        }
        for (int i = 0; i < SBOX_SIZE; i++) {
            j = (j + sbox[i] + (key[i % key.length]) & 0xFF) % SBOX_SIZE;
            swap(i, j, sbox);
        }
        return sbox;
    }

    private void swap(int i, int j, int[] sbox) {
        int temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }

    public void setKey(String key) {
        if (!(key.length() >= KEY_MIN_SIZE && key.length() < SBOX_SIZE)) {
            throw new IllegalArgumentException("Wrong size of key. Need to be in range between "
                    + KEY_MIN_SIZE + " to " + (SBOX_SIZE - 1));
        }
        this.key = key.getBytes();
    }

}

