import java.util.Arrays;

public class AES {

    public static final int SUCCESS = 0;
    public static final int ERROR_AES_UNKNOWN_KEYSIZE = 1;
    public static final int ERROR_MEMORY_ALLOCATION_FAILED = 2;

    public enum KeySize {
        SIZE_16(16), SIZE_24(24), SIZE_32(32);
        public final int value;
        KeySize(int v) { this.value = v; }
    }

    // S-Box
    private static final byte[] sbox = new byte[]{
        (byte)0x63,(byte)0x7c,(byte)0x77,(byte)0x7b,(byte)0xf2,(byte)0x6b,(byte)0x6f,(byte)0xc5,
        (byte)0x30,(byte)0x01,(byte)0x67,(byte)0x2b,(byte)0xfe,(byte)0xd7,(byte)0xab,(byte)0x76,
        (byte)0xca,(byte)0x82,(byte)0xc9,(byte)0x7d,(byte)0xfa,(byte)0x59,(byte)0x47,(byte)0xf0,
        (byte)0xad,(byte)0xd4,(byte)0xa2,(byte)0xaf,(byte)0x9c,(byte)0xa4,(byte)0x72,(byte)0xc0,
        (byte)0xb7,(byte)0xfd,(byte)0x93,(byte)0x26,(byte)0x36,(byte)0x3f,(byte)0xf7,(byte)0xcc,
        (byte)0x34,(byte)0xa5,(byte)0xe5,(byte)0xf1,(byte)0x71,(byte)0xd8,(byte)0x31,(byte)0x15,
        (byte)0x04,(byte)0xc7,(byte)0x23,(byte)0xc3,(byte)0x18,(byte)0x96,(byte)0x05,(byte)0x9a,
        (byte)0x07,(byte)0x12,(byte)0x80,(byte)0xe2,(byte)0xeb,(byte)0x27,(byte)0xb2,(byte)0x75,
        (byte)0x09,(byte)0x83,(byte)0x2c,(byte)0x1a,(byte)0x1b,(byte)0x6e,(byte)0x5a,(byte)0xa0,
        (byte)0x52,(byte)0x3b,(byte)0xd6,(byte)0xb3,(byte)0x29,(byte)0xe3,(byte)0x2f,(byte)0x84,
        (byte)0x53,(byte)0xd1,(byte)0x00,(byte)0xed,(byte)0x20,(byte)0xfc,(byte)0xb1,(byte)0x5b,
        (byte)0x6a,(byte)0xcb,(byte)0xbe,(byte)0x39,(byte)0x4a,(byte)0x4c,(byte)0x58,(byte)0xcf,
        (byte)0xd0,(byte)0xef,(byte)0xaa,(byte)0xfb,(byte)0x43,(byte)0x4d,(byte)0x33,(byte)0x85,
        (byte)0x45,(byte)0xf9,(byte)0x02,(byte)0x7f,(byte)0x50,(byte)0x3c,(byte)0x9f,(byte)0xa8,
        (byte)0x51,(byte)0xa3,(byte)0x40,(byte)0x8f,(byte)0x92,(byte)0x9d,(byte)0x38,(byte)0xf5,
        (byte)0xbc,(byte)0xb6,(byte)0xda,(byte)0x21,(byte)0x10,(byte)0xff,(byte)0xf3,(byte)0xd2,
        (byte)0xcd,(byte)0x0c,(byte)0x13,(byte)0xec,(byte)0x5f,(byte)0x97,(byte)0x44,(byte)0x17,
        (byte)0xc4,(byte)0xa7,(byte)0x7e,(byte)0x3d,(byte)0x64,(byte)0x5d,(byte)0x19,(byte)0x73,
        (byte)0x60,(byte)0x81,(byte)0x4f,(byte)0xdc,(byte)0x22,(byte)0x2a,(byte)0x90,(byte)0x88,
        (byte)0x46,(byte)0xee,(byte)0xb8,(byte)0x14,(byte)0xde,(byte)0x5e,(byte)0x0b,(byte)0xdb,
        (byte)0xe0,(byte)0x32,(byte)0x3a,(byte)0x0a,(byte)0x49,(byte)0x06,(byte)0x24,(byte)0x5c,
        (byte)0xc2,(byte)0xd3,(byte)0xac,(byte)0x62,(byte)0x91,(byte)0x95,(byte)0xe4,(byte)0x79,
        (byte)0xe7,(byte)0xc8,(byte)0x37,(byte)0x6d,(byte)0x8d,(byte)0xd5,(byte)0x4e,(byte)0xa9,
        (byte)0x6c,(byte)0x56,(byte)0xf4,(byte)0xea,(byte)0x65,(byte)0x7a,(byte)0xae,(byte)0x08,
        (byte)0xba,(byte)0x78,(byte)0x25,(byte)0x2e,(byte)0x1c,(byte)0xa6,(byte)0xb4,(byte)0xc6,
        (byte)0xe8,(byte)0xdd,(byte)0x74,(byte)0x1f,(byte)0x4b,(byte)0xbd,(byte)0x8b,(byte)0x8a,
        (byte)0x70,(byte)0x3e,(byte)0xb5,(byte)0x66,(byte)0x48,(byte)0x03,(byte)0xf6,(byte)0x0e,
        (byte)0x61,(byte)0x35,(byte)0x57,(byte)0xb9,(byte)0x86,(byte)0xc1,(byte)0x1d,(byte)0x9e,
        (byte)0xe1,(byte)0xf8,(byte)0x98,(byte)0x11,(byte)0x69,(byte)0xd9,(byte)0x8e,(byte)0x94,
        (byte)0x9b,(byte)0x1e,(byte)0x87,(byte)0xe9,(byte)0xce,(byte)0x55,(byte)0x28,(byte)0xdf,
        (byte)0x8c,(byte)0xa1,(byte)0x89,(byte)0x0d,(byte)0xbf,(byte)0xe6,(byte)0x42,(byte)0x68,
        (byte)0x41,(byte)0x99,(byte)0x2d,(byte)0x0f,(byte)0xb0,(byte)0x54,(byte)0xbb,(byte)0x16
    };

    // Inverse S-Box
    private static final byte[] rsbox = new byte[]{
        (byte)0x52,(byte)0x09,(byte)0x6a,(byte)0xd5,(byte)0x30,(byte)0x36,(byte)0xa5,(byte)0x38,
        (byte)0xbf,(byte)0x40,(byte)0xa3,(byte)0x9e,(byte)0x81,(byte)0xf3,(byte)0xd7,(byte)0xfb,
        (byte)0x7c,(byte)0xe3,(byte)0x39,(byte)0x82,(byte)0x9b,(byte)0x2f,(byte)0xff,(byte)0x87,
        (byte)0x34,(byte)0x8e,(byte)0x43,(byte)0x44,(byte)0xc4,(byte)0xde,(byte)0xe9,(byte)0xcb,
        (byte)0x54,(byte)0x7b,(byte)0x94,(byte)0x32,(byte)0xa6,(byte)0xc2,(byte)0x23,(byte)0x3d,
        (byte)0xee,(byte)0x4c,(byte)0x95,(byte)0x0b,(byte)0x42,(byte)0xfa,(byte)0xc3,(byte)0x4e,
        (byte)0x08,(byte)0x2e,(byte)0xa1,(byte)0x66,(byte)0x28,(byte)0xd9,(byte)0x24,(byte)0xb2,
        (byte)0x76,(byte)0x5b,(byte)0xa2,(byte)0x49,(byte)0x6d,(byte)0x8b,(byte)0xd1,(byte)0x25,
        (byte)0x72,(byte)0xf8,(byte)0xf6,(byte)0x64,(byte)0x86,(byte)0x68,(byte)0x98,(byte)0x16,
        (byte)0xd4,(byte)0xa4,(byte)0x5c,(byte)0xcc,(byte)0x5d,(byte)0x65,(byte)0xb6,(byte)0x92,
        (byte)0x6c,(byte)0x70,(byte)0x48,(byte)0x50,(byte)0xfd,(byte)0xed,(byte)0xb9,(byte)0xda,
        (byte)0x5e,(byte)0x15,(byte)0x46,(byte)0x57,(byte)0xa7,(byte)0x8d,(byte)0x9d,(byte)0x84,
        (byte)0x90,(byte)0xd8,(byte)0xab,(byte)0x00,(byte)0x8c,(byte)0xbc,(byte)0xd3,(byte)0x0a,
        (byte)0xf7,(byte)0xe4,(byte)0x58,(byte)0x05,(byte)0xb8,(byte)0xb3,(byte)0x45,(byte)0x06,
        (byte)0xd0,(byte)0x2c,(byte)0x1e,(byte)0x8f,(byte)0xca,(byte)0x3f,(byte)0x0f,(byte)0x02,
        (byte)0xc1,(byte)0xaf,(byte)0xbd,(byte)0x03,(byte)0x01,(byte)0x13,(byte)0x8a,(byte)0x6b,
        (byte)0x3a,(byte)0x91,(byte)0x11,(byte)0x41,(byte)0x4f,(byte)0x67,(byte)0xdc,(byte)0xea,
        (byte)0x97,(byte)0xf2,(byte)0xcf,(byte)0xce,(byte)0xf0,(byte)0xb4,(byte)0xe6,(byte)0x73,
        (byte)0x96,(byte)0xac,(byte)0x74,(byte)0x22,(byte)0xe7,(byte)0xad,(byte)0x35,(byte)0x85,
        (byte)0xe2,(byte)0xf9,(byte)0x37,(byte)0xe8,(byte)0x1c,(byte)0x75,(byte)0xdf,(byte)0x6e,
        (byte)0x47,(byte)0xf1,(byte)0x1a,(byte)0x71,(byte)0x1d,(byte)0x29,(byte)0xc5,(byte)0x89,
        (byte)0x6f,(byte)0xb7,(byte)0x62,(byte)0x0e,(byte)0xaa,(byte)0x18,(byte)0xbe,(byte)0x1b,
        (byte)0xfc,(byte)0x56,(byte)0x3e,(byte)0x4b,(byte)0xc6,(byte)0xd2,(byte)0x79,(byte)0x20,
        (byte)0x9a,(byte)0xdb,(byte)0xc0,(byte)0xfe,(byte)0x78,(byte)0xcd,(byte)0x5a,(byte)0xf4,
        (byte)0x1f,(byte)0xdd,(byte)0xa8,(byte)0x33,(byte)0x88,(byte)0x07,(byte)0xc7,(byte)0x31,
        (byte)0xb1,(byte)0x12,(byte)0x10,(byte)0x59,(byte)0x27,(byte)0x80,(byte)0xec,(byte)0x5f,
        (byte)0x60,(byte)0x51,(byte)0x7f,(byte)0xa9,(byte)0x19,(byte)0xb5,(byte)0x4a,(byte)0x0d,
        (byte)0x2d,(byte)0xe5,(byte)0x7a,(byte)0x9f,(byte)0x93,(byte)0xc9,(byte)0x9c,(byte)0xef,
        (byte)0xa0,(byte)0xe0,(byte)0x3b,(byte)0x4d,(byte)0xae,(byte)0x2a,(byte)0xf5,(byte)0xb0,
        (byte)0xc8,(byte)0xeb,(byte)0xbb,(byte)0x3c,(byte)0x83,(byte)0x53,(byte)0x99,(byte)0x61,
        (byte)0x17,(byte)0x2b,(byte)0x04,(byte)0x7e,(byte)0xba,(byte)0x77,(byte)0xd6,(byte)0x26,
        (byte)0xe1,(byte)0x69,(byte)0x14,(byte)0x63,(byte)0x55,(byte)0x21,(byte)0x0c,(byte)0x7d
    };

    // Rcon
    private static final byte[] Rcon = new byte[]{
        (byte)0x8d,(byte)0x01,(byte)0x02,(byte)0x04,(byte)0x08,(byte)0x10,(byte)0x20,(byte)0x40,
        (byte)0x80,(byte)0x1b,(byte)0x36,(byte)0x6c,(byte)0xd8,(byte)0xab,(byte)0x4d,(byte)0x9a,
        (byte)0x2f,(byte)0x5e,(byte)0xbc,(byte)0x63,(byte)0xc6,(byte)0x97,(byte)0x35,(byte)0x6a,
        (byte)0xd4,(byte)0xb3,(byte)0x7d,(byte)0xfa,(byte)0xef,(byte)0xc5,(byte)0x91,(byte)0x39,
        (byte)0x72,(byte)0xe4,(byte)0xd3,(byte)0xbd,(byte)0x61,(byte)0xc2,(byte)0x9f,(byte)0x25,
        (byte)0x4a,(byte)0x94,(byte)0x33,(byte)0x66,(byte)0xcc,(byte)0x83,(byte)0x1d,(byte)0x3a,
        (byte)0x74,(byte)0xe8,(byte)0xcb,(byte)0x8d,(byte)0x01,(byte)0x02,(byte)0x04,(byte)0x08,
        (byte)0x10,(byte)0x20,(byte)0x40,(byte)0x80,(byte)0x1b,(byte)0x36,(byte)0x6c,(byte)0xd8,
        (byte)0xab,(byte)0x4d,(byte)0x9a,(byte)0x2f,(byte)0x5e,(byte)0xbc,(byte)0x63,(byte)0xc6,
        (byte)0x97,(byte)0x35,(byte)0x6a,(byte)0xd4,(byte)0xb3,(byte)0x7d,(byte)0xfa,(byte)0xef,
        (byte)0xc5,(byte)0x91,(byte)0x39,(byte)0x72,(byte)0xe4,(byte)0xd3,(byte)0xbd,(byte)0x61,
        (byte)0xc2,(byte)0x9f,(byte)0x25,(byte)0x4a,(byte)0x94,(byte)0x33,(byte)0x66,(byte)0xcc,
        (byte)0x83,(byte)0x1d,(byte)0x3a,(byte)0x74,(byte)0xe8,(byte)0xcb,(byte)0x8d,(byte)0x01,
        (byte)0x02,(byte)0x04,(byte)0x08,(byte)0x10,(byte)0x20,(byte)0x40,(byte)0x80,(byte)0x1b,
        (byte)0x36,(byte)0x6c,(byte)0xd8,(byte)0xab,(byte)0x4d,(byte)0x9a,(byte)0x2f,(byte)0x5e,
        (byte)0xbc,(byte)0x63,(byte)0xc6,(byte)0x97,(byte)0x35,(byte)0x6a,(byte)0xd4,(byte)0xb3,
        (byte)0x7d,(byte)0xfa,(byte)0xef,(byte)0xc5,(byte)0x91,(byte)0x39,(byte)0x72,(byte)0xe4,
        (byte)0xd3,(byte)0xbd,(byte)0x61,(byte)0xc2,(byte)0x9f,(byte)0x25,(byte)0x4a,(byte)0x94,
        (byte)0x33,(byte)0x66,(byte)0xcc,(byte)0x83,(byte)0x1d,(byte)0x3a,(byte)0x74,(byte)0xe8,
        (byte)0xcb,(byte)0x8d,(byte)0x01,(byte)0x02,(byte)0x04,(byte)0x08,(byte)0x10,(byte)0x20,
        (byte)0x40,(byte)0x80,(byte)0x1b,(byte)0x36,(byte)0x6c,(byte)0xd8,(byte)0xab,(byte)0x4d,
        (byte)0x9a,(byte)0x2f,(byte)0x5e,(byte)0xbc,(byte)0x63,(byte)0xc6,(byte)0x97,(byte)0x35,
        (byte)0x6a,(byte)0xd4,(byte)0xb3,(byte)0x7d,(byte)0xfa,(byte)0xef,(byte)0xc5,(byte)0x91,
        (byte)0x39,(byte)0x72,(byte)0xe4,(byte)0xd3,(byte)0xbd,(byte)0x61,(byte)0xc2,(byte)0x9f,
        (byte)0x25,(byte)0x4a,(byte)0x94,(byte)0x33,(byte)0x66,(byte)0xcc,(byte)0x83,(byte)0x1d,
        (byte)0x3a,(byte)0x74,(byte)0xe8,(byte)0xcb,(byte)0x8d,(byte)0x01,(byte)0x02,(byte)0x04,
        (byte)0x08,(byte)0x10,(byte)0x20,(byte)0x40,(byte)0x80,(byte)0x1b,(byte)0x36,(byte)0x6c,
        (byte)0xd8,(byte)0xab,(byte)0x4d,(byte)0x9a,(byte)0x2f,(byte)0x5e,(byte)0xbc,(byte)0x63,
        (byte)0xc6,(byte)0x97,(byte)0x35,(byte)0x6a,(byte)0xd4,(byte)0xb3,(byte)0x7d,(byte)0xfa,
        (byte)0xef,(byte)0xc5,(byte)0x91,(byte)0x39,(byte)0x72,(byte)0xe4,(byte)0xd3,(byte)0xbd,
        (byte)0x61,(byte)0xc2,(byte)0x9f,(byte)0x25,(byte)0x4a,(byte)0x94,(byte)0x33,(byte)0x66,
        (byte)0xcc,(byte)0x83,(byte)0x1d,(byte)0x3a,(byte)0x74,(byte)0xe8,(byte)0xcb
    };

    // S-Box value
    public static byte getSBoxValue(byte num) {
        return sbox[num & 0xFF];
    }

    public static byte getSBoxInvert(byte num) {
        return rsbox[num & 0xFF];
    }

    public static void rotate(byte[] word) {
        byte c = word[0];
        for (int i = 0; i < 3; i++) {
            word[i] = word[i + 1];
        }
        word[3] = c;
    }

    public static byte getRconValue(int num) {
        return Rcon[num];
    }

    public static void core(byte[] word, int iteration) {
        rotate(word);
        for (int i = 0; i < 4; ++i) {
            word[i] = getSBoxValue(word[i]);
        }
        word[0] ^= getRconValue(iteration);
    }

    public static void expandKey(byte[] expandedKey, byte[] key, KeySize size, int expandedKeySize) {
        int currentSize = 0;
        int rconIteration = 1;
        byte[] t = new byte[4];

        System.arraycopy(key, 0, expandedKey, 0, size.value);
        currentSize += size.value;

        while (currentSize < expandedKeySize) {
            for (int i = 0; i < 4; i++)
                t[i] = expandedKey[(currentSize - 4) + i];

            if (currentSize % size.value == 0)
                core(t, rconIteration++);

            if (size == KeySize.SIZE_32 && (currentSize % size.value == 16)) {
                for (int i = 0; i < 4; i++)
                    t[i] = getSBoxValue(t[i]);
            }

            for (int i = 0; i < 4; i++) {
                expandedKey[currentSize] = (byte)(expandedKey[currentSize - size.value] ^ t[i]);
                currentSize++;
            }
        }
    }

    public static void subBytes(byte[] state) {
        for (int i = 0; i < 16; i++)
            state[i] = getSBoxValue(state[i]);
    }

    public static void invSubBytes(byte[] state) {
        for (int i = 0; i < 16; i++)
            state[i] = getSBoxInvert(state[i]);
    }

    public static void shiftRows(byte[] state) {
        for (int i = 0; i < 4; i++)
            shiftRow(state, i);
    }

    public static void invShiftRows(byte[] state) {
        for (int i = 0; i < 4; i++)
            invShiftRow(state, i);
    }

    public static void shiftRow(byte[] state, int nbr) {
        for (int i = 0; i < nbr; i++) {
            byte tmp = state[nbr * 4];
            for (int j = 0; j < 3; j++)
                state[nbr * 4 + j] = state[nbr * 4 + j + 1];
            state[nbr * 4 + 3] = tmp;
        }
    }

    public static void invShiftRow(byte[] state, int nbr) {
        for (int i = 0; i < nbr; i++) {
            byte tmp = state[nbr * 4 + 3];
            for (int j = 3; j > 0; j--)
                state[nbr * 4 + j] = state[nbr * 4 + j - 1];
            state[nbr * 4] = tmp;
        }
    }

    public static void addRoundKey(byte[] state, byte[] roundKey) {
        for (int i = 0; i < 16; i++)
            state[i] ^= roundKey[i];
    }

    public static byte galoisMultiplication(byte a, byte b) {
        byte p = 0;
        for (int counter = 0; counter < 8; counter++) {
            if ((b & 1) == 1)
                p ^= a;
            boolean hiBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (hiBitSet)
                a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    public static void mixColumns(byte[] state) {
        byte[] column = new byte[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++)
                column[j] = state[j * 4 + i];
            mixColumn(column);
            for (int j = 0; j < 4; j++)
                state[j * 4 + i] = column[j];
        }
    }

    public static void mixColumn(byte[] column) {
        byte[] cpy = column.clone();
        column[0] = (byte)(galoisMultiplication(cpy[0], (byte)2) ^ galoisMultiplication(cpy[1], (byte)3) ^ cpy[2] ^ cpy[3]);
        column[1] = (byte)(cpy[0] ^ galoisMultiplication(cpy[1], (byte)2) ^ galoisMultiplication(cpy[2], (byte)3) ^ cpy[3]);
        column[2] = (byte)(cpy[0] ^ cpy[1] ^ galoisMultiplication(cpy[2], (byte)2) ^ galoisMultiplication(cpy[3], (byte)3));
        column[3] = (byte)(galoisMultiplication(cpy[0], (byte)3) ^ cpy[1] ^ cpy[2] ^ galoisMultiplication(cpy[3], (byte)2));
    }

    public static void invMixColumns(byte[] state) {
        byte[] column = new byte[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++)
                column[j] = state[j * 4 + i];
            invMixColumn(column);
            for (int j = 0; j < 4; j++)
                state[j * 4 + i] = column[j];
        }
    }

    public static void invMixColumn(byte[] column) {
        byte[] cpy = column.clone();
        column[0] = (byte)(galoisMultiplication(cpy[0], (byte)0x0e) ^ galoisMultiplication(cpy[1], (byte)0x0b) ^ galoisMultiplication(cpy[2], (byte)0x0d) ^ galoisMultiplication(cpy[3], (byte)0x09));
        column[1] = (byte)(galoisMultiplication(cpy[0], (byte)0x09) ^ galoisMultiplication(cpy[1], (byte)0x0e) ^ galoisMultiplication(cpy[2], (byte)0x0b) ^ galoisMultiplication(cpy[3], (byte)0x0d));
        column[2] = (byte)(galoisMultiplication(cpy[0], (byte)0x0d) ^ galoisMultiplication(cpy[1], (byte)0x09) ^ galoisMultiplication(cpy[2], (byte)0x0e) ^ galoisMultiplication(cpy[3], (byte)0x0b));
        column[3] = (byte)(galoisMultiplication(cpy[0], (byte)0x0b) ^ galoisMultiplication(cpy[1], (byte)0x0d) ^ galoisMultiplication(cpy[2], (byte)0x09) ^ galoisMultiplication(cpy[3], (byte)0x0e));
    }

    public static void aesRound(byte[] state, byte[] roundKey) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKey);
    }

    public static void invAesRound(byte[] state, byte[] roundKey) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKey);
        invMixColumns(state);
    }

    public static void createRoundKey(byte[] expandedKey, int round, byte[] roundKey) {
        for (int i = 0; i < 16; i++)
            roundKey[i] = expandedKey[round * 16 + i];
    }

    public static void aesMain(byte[] state, byte[] expandedKey, int nbrRounds) {
        byte[] roundKey = new byte[16];
        createRoundKey(expandedKey, 0, roundKey);
        addRoundKey(state, roundKey);
        for (int i = 1; i < nbrRounds; i++) {
            createRoundKey(expandedKey, i, roundKey);
            aesRound(state, roundKey);
        }
        createRoundKey(expandedKey, nbrRounds, roundKey);
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKey);
    }

    public static void invAesMain(byte[] state, byte[] expandedKey, int nbrRounds) {
        byte[] roundKey = new byte[16];
        createRoundKey(expandedKey, nbrRounds, roundKey);
        addRoundKey(state, roundKey);
        for (int i = nbrRounds - 1; i > 0; i--) {
            createRoundKey(expandedKey, i, roundKey);
            invAesRound(state, roundKey);
        }
        createRoundKey(expandedKey, 0, roundKey);
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKey);
    }

    public static int aesEncrypt(byte[] input, byte[] output, byte[] key, KeySize size) {
        int nbrRounds;
        switch (size) {
            case SIZE_16: nbrRounds = 10; break;
            case SIZE_24: nbrRounds = 12; break;
            case SIZE_32: nbrRounds = 14; break;
            default: return ERROR_AES_UNKNOWN_KEYSIZE;
        }
        int expandedKeySize = 16 * (nbrRounds + 1);
        byte[] expandedKey = new byte[expandedKeySize];
        byte[] block = new byte[16];

        // Map input to block
        for (int i = 0; i < 16; i++)
            block[i] = input[i];

        expandKey(expandedKey, key, size, expandedKeySize);
        aesMain(block, expandedKey, nbrRounds);

        // Unmap block to output
        for (int i = 0; i < 16; i++)
            output[i] = block[i];

        return SUCCESS;
    }

    public static int aesDecrypt(byte[] input, byte[] output, byte[] key, KeySize size) {
        int nbrRounds;
        switch (size) {
            case SIZE_16: nbrRounds = 10; break;
            case SIZE_24: nbrRounds = 12; break;
            case SIZE_32: nbrRounds = 14; break;
            default: return ERROR_AES_UNKNOWN_KEYSIZE;
        }
        int expandedKeySize = 16 * (nbrRounds + 1);
        byte[] expandedKey = new byte[expandedKeySize];
        byte[] block = new byte[16];

        // Map input to block
        for (int i = 0; i < 16; i++)
            block[i] = input[i];

        expandKey(expandedKey, key, size, expandedKeySize);
        invAesMain(block, expandedKey, nbrRounds);

        // Unmap block to output
        for (int i = 0; i < 16; i++)
            output[i] = block[i];

        return SUCCESS;
    }

    public static void main(String[] args) {
        int expandedKeySize = 176;
        byte[] expandedKey = new byte[expandedKeySize];
        byte[] key = new byte[]{'k','k','k','k','e','e','e','e','y','y','y','y','.','.','.','.'};
        KeySize size = KeySize.SIZE_16;
        byte[] plaintext = new byte[]{'a','b','c','d','e','f','1','2','3','4','5','6','7','8','9','0'};
        byte[] ciphertext = new byte[16];
        byte[] decryptedtext = new byte[16];

        System.out.println("**************************************************");
        System.out.println("* Basic implementation of AES algorithm in Java  *");
        System.out.println("**************************************************\n");

        System.out.println("Cipher Key (HEX format):");
        for (int i = 0; i < 16; i++)
            System.out.printf("%02x%c", key[i], ((i + 1) % 16) == 0 ? '\n' : ' ');

        expandKey(expandedKey, key, size, expandedKeySize);
        System.out.println("\nExpanded Key (HEX format):");
        for (int i = 0; i < expandedKeySize; i++)
            System.out.printf("%02x%c", expandedKey[i], ((i + 1) % 16) == 0 ? '\n' : ' ');

        System.out.println("\nPlaintext (HEX format):");
        for (int i = 0; i < 16; i++)
            System.out.printf("%02x%c", plaintext[i], ((i + 1) % 16) == 0 ? '\n' : ' ');

        aesEncrypt(plaintext, ciphertext, key, size);
        System.out.println("\nCiphertext (HEX format):");
        for (int i = 0; i < 16; i++)
            System.out.printf("%02x%c", ciphertext[i], ((i + 1) % 16) == 0 ? '\n' : ' ');

        aesDecrypt(ciphertext, decryptedtext, key, size);
        System.out.println("\nDecrypted Text (HEX format):");
        for (int i = 0; i < 16; i++)
            System.out.printf("%02x%c", decryptedtext[i], ((i + 1) % 16) == 0 ? '\n' : ' ');

        System.out.println("\nDecrypted Text (ASCII):");
        for (int i = 0; i < 16; i++)
            System.out.print((char)decryptedtext[i]);
        System.out.println();
    }
}
