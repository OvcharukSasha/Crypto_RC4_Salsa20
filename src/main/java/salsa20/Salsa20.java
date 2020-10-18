package salsa20;

public class Salsa20 {

    private final static int stateSize = 16; // 16, 32 bit ints = 64 bytes

    private final static byte[] constant32 = "expand 32-byte k".getBytes();
    private final static byte[] constant16 = "expand 16-byte k".getBytes();

    private int index = 0;
    private int[] engineState = new int[stateSize];
    private int[] buffer = new int[stateSize];
    private byte[] keyStream = new byte[stateSize * 4]; // expanded state
    private byte[] workingKey;
    private byte[] workingIV;
    private boolean initialised = false;

    private int counter0, counter1, counter2;

    public void init(byte[] key, byte[] iv) {
        if (iv == null || iv.length != 8) {
            throw new IllegalArgumentException("Expected 8 bytes of IV");
        }
        workingKey = key;
        workingIV = iv;

        setKey(workingKey, workingIV);
    }

    public final byte[] crypt(byte[] data, int position, int length) {
        byte[] buffer = new byte[length];
        crypt(data, position, length, buffer, 0);
        return buffer;
    }


    public void crypt(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (!initialised) {
            throw new IllegalStateException("Salsa20 is not initialised");
        }

        if ((inOff + len) > in.length) {
            throw new IllegalStateException("input buffer too short");
        }

        if ((outOff + len) > out.length) {
            throw new IllegalStateException("output buffer too short");
        }

        if (isOutOfLimit(len)) {
            throw new IllegalStateException("2^70 byte limit per IV would be exceeded; Change IV");
        }

        for (int i = 0; i < len; i++) {
            if (index == 0) {
                salsa20WordToByte(engineState, keyStream);
                engineState[8]++;
                if (engineState[8] == 0) {
                    engineState[9]++;
                }
            }
            out[i + outOff] = (byte) (keyStream[index] ^ in[i + inOff]);
            index = (index + 1) & 63;
        }
    }


    private void setKey(byte[] keyBytes, byte[] ivBytes) {
        workingKey = keyBytes;
        workingIV = ivBytes;

        index = 0;
        resetCounter();
        int offset = 0;
        byte[] constants;

        // Key
        engineState[1] = getIntFromBytesLittleEndian(workingKey, 0);
        engineState[2] = getIntFromBytesLittleEndian(workingKey, 4);
        engineState[3] = getIntFromBytesLittleEndian(workingKey, 8);
        engineState[4] = getIntFromBytesLittleEndian(workingKey, 12);

        if (workingKey.length == 32) {
            constants = constant32;
            offset = 16;
        } else {
            constants = constant16;
        }

        engineState[11] = getIntFromBytesLittleEndian(workingKey, offset);
        engineState[12] = getIntFromBytesLittleEndian(workingKey, offset + 4);
        engineState[13] = getIntFromBytesLittleEndian(workingKey, offset + 8);
        engineState[14] = getIntFromBytesLittleEndian(workingKey, offset + 12);
        engineState[0] = getIntFromBytesLittleEndian(constants, 0);
        engineState[5] = getIntFromBytesLittleEndian(constants, 4);
        engineState[10] = getIntFromBytesLittleEndian(constants, 8);
        engineState[15] = getIntFromBytesLittleEndian(constants, 12);

        // IV
        engineState[6] = getIntFromBytesLittleEndian(workingIV, 0);
        engineState[7] = getIntFromBytesLittleEndian(workingIV, 4);
        engineState[8] = engineState[9] = 0;

        initialised = true;
    }

    private void salsa20WordToByte(int[] input, byte[] output) {
        System.arraycopy(input, 0, buffer, 0, input.length);

        for (int i = 0; i < 10; i++) {
            buffer[4] ^= rotateLeft((buffer[0] + buffer[12]), 7);
            buffer[8] ^= rotateLeft((buffer[4] + buffer[0]), 9);
            buffer[12] ^= rotateLeft((buffer[8] + buffer[4]), 13);
            buffer[0] ^= rotateLeft((buffer[12] + buffer[8]), 18);
            buffer[9] ^= rotateLeft((buffer[5] + buffer[1]), 7);
            buffer[13] ^= rotateLeft((buffer[9] + buffer[5]), 9);
            buffer[1] ^= rotateLeft((buffer[13] + buffer[9]), 13);
            buffer[5] ^= rotateLeft((buffer[1] + buffer[13]), 18);
            buffer[14] ^= rotateLeft((buffer[10] + buffer[6]), 7);
            buffer[2] ^= rotateLeft((buffer[14] + buffer[10]), 9);
            buffer[6] ^= rotateLeft((buffer[2] + buffer[14]), 13);
            buffer[10] ^= rotateLeft((buffer[6] + buffer[2]), 18);
            buffer[3] ^= rotateLeft((buffer[15] + buffer[11]), 7);
            buffer[7] ^= rotateLeft((buffer[3] + buffer[15]), 9);
            buffer[11] ^= rotateLeft((buffer[7] + buffer[3]), 13);
            buffer[15] ^= rotateLeft((buffer[11] + buffer[7]), 18);
            buffer[1] ^= rotateLeft((buffer[0] + buffer[3]), 7);
            buffer[2] ^= rotateLeft((buffer[1] + buffer[0]), 9);
            buffer[3] ^= rotateLeft((buffer[2] + buffer[1]), 13);
            buffer[0] ^= rotateLeft((buffer[3] + buffer[2]), 18);
            buffer[6] ^= rotateLeft((buffer[5] + buffer[4]), 7);
            buffer[7] ^= rotateLeft((buffer[6] + buffer[5]), 9);
            buffer[4] ^= rotateLeft((buffer[7] + buffer[6]), 13);
            buffer[5] ^= rotateLeft((buffer[4] + buffer[7]), 18);
            buffer[11] ^= rotateLeft((buffer[10] + buffer[9]), 7);
            buffer[8] ^= rotateLeft((buffer[11] + buffer[10]), 9);
            buffer[9] ^= rotateLeft((buffer[8] + buffer[11]), 13);
            buffer[10] ^= rotateLeft((buffer[9] + buffer[8]), 18);
            buffer[12] ^= rotateLeft((buffer[15] + buffer[14]), 7);
            buffer[13] ^= rotateLeft((buffer[12] + buffer[15]), 9);
            buffer[14] ^= rotateLeft((buffer[13] + buffer[12]), 13);
            buffer[15] ^= rotateLeft((buffer[14] + buffer[13]), 18);
        }

        int offset = 0;
        for (int i = 0; i < stateSize; i++) {
            intToByteLittle(buffer[i] + input[i], output, offset);
            offset += 4;
        }

        for (int i = stateSize; i < buffer.length; i++) {
            intToByteLittle(buffer[i], output, offset);
            offset += 4;
        }
    }

    private byte[] intToByteLittle(int x, byte[] out, int off) {
        out[off] = (byte) x;
        out[off + 1] = (byte) (x >>> 8);
        out[off + 2] = (byte) (x >>> 16);
        out[off + 3] = (byte) (x >>> 24);
        return out;
    }

    private int rotateLeft(int x, int y) {
        return (x << y) | (x >>> -y);
    }

    private int getIntFromBytesLittleEndian(byte[] x, int offset) { //little endian order
        return ((x[offset] & 255)) |
                ((x[offset + 1] & 255) << 8) |
                ((x[offset + 2] & 255) << 16) |
                (x[offset + 3] << 24);
    }

    private void resetCounter() {
        counter0 = 0;
        counter1 = 0;
        counter2 = 0;
    }

    private boolean isOutOfLimit(int len) {
        if (counter0 >= 0) {
            counter0 += len;
        } else {
            counter0 += len;
            if (counter0 >= 0) {
                counter1++;
                if (counter1 == 0) {
                    counter2++;
                    // 2^(32 + 32 + 6)
                    return (counter2 & 0x20) != 0;
                }
            }
        }
        return false;
    }

}