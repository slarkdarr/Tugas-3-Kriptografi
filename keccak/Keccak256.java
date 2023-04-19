import java.math.BigInteger;
import java.util.Arrays;

/**
 * This class implements Keccak-256 hash function based on specifications provided at
 * https://keccak.team/keccak_specs_summary.html
 */
public class Keccak256 {

    private static final int R = 1088;
    private static final int C = 1600 - R;
    private static final int BLOCK_SIZE = C / 8;
    private static final int OUTPUT_SIZE = 32;
    private static final long[] ROUND_CONSTANTS = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[][] ROTATION_OFFSETS = {
            {0, 1, 2, 3, 4}, {0, 1, 2, 3, 4}, {0, 1, 2, 3, 4}, {0, 1, 2, 3, 4}, {0, 1, 2, 3, 4}
    };

    public static byte[] hash(byte[] message) {

        BigInteger[][] state = initializeState();

        byte[] paddedMessage = pad(message);
        int blockCount = paddedMessage.length / BLOCK_SIZE;

        for (int i = 0; i < blockCount; i++) {
            absorb(state, paddedMessage, i * BLOCK_SIZE);
            keccak(state);
        }

        byte[] hash = new byte[OUTPUT_SIZE];
        for (int i = 0; i < OUTPUT_SIZE; i++) {
            squeeze(hash, state);
            keccak(state);
        }

        return hash;
    }

    private static BigInteger[][] initializeState() {
        BigInteger[][] state = new BigInteger[5][5];
        for (int i = 0; i < 5; i++) {
            Arrays.fill(state[i], BigInteger.ZERO);
        }
        return state;
    }

    private static byte[] pad(byte[] message) {
        int length = message.length;
        if (length % BLOCK_SIZE == 0) {
            return message;
        }

        int paddedLength = ((length / BLOCK_SIZE) + 1) * BLOCK_SIZE;

        byte[] paddedMessage = new byte[paddedLength];
        System.arraycopy(message, 0, paddedMessage, 0, length);
        paddedMessage[length] = (byte) 0x01;
        paddedMessage[paddedLength - 1] |= (byte) 0x80;

        return paddedMessage;
    }

    private static void absorb(BigInteger[][] state, byte[] message, int offset) {
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                int index = (j * 5) + i;
                byte[] bytes = Arrays.copyOfRange(message, offset + index, offset + index + 8);
                state[i][j] = state[i][j].xor(new BigInteger(1, bytes));
            }
        }
    }

    private static void squeeze(byte[] hash, BigInteger[][] state) {
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                int index = (j * 5) + i;
                byte[] bytes = state[i][j].toByteArray();
                int length = bytes.length;
                if (bytes.length < 8) {
                    byte[] paddedBytes = new byte[8];
                    System.arraycopy(bytes, 0, paddedBytes, 8 - length, length);
                    bytes = paddedBytes;
                }
                System.arraycopy(bytes, 0, hash, index, 8);
            }
        }
    }

    private static void keccak(BigInteger[][] state) {
        for (long round : ROUND_CONSTANTS) {
            keccakF(state, round);
        }
    }

    private static void keccakF(BigInteger[][] state, long round) {
        BigInteger[] C = new BigInteger[5];
        BigInteger[] D = new BigInteger[5];

        // 0 step
        for (int i = 0; i < 5; i++) {
            C[i] = state[i][0].xor(state[i][1]).xor(state[i][2]).xor(state[i][3]).xor(state[i][4]);
        }

        for (int i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5].xor(BigInteger.valueOf(Long.rotateLeft(C[(i + 1) % 5].longValue(), 1)));
        }

        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                state[i][j] = state[i][j].xor(D[i]);
            }
        }

        BigInteger[][] B = new BigInteger[5][5];

        // ρ and π step
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                B[j][(2 * i + 3 * j) % 5] = BigInteger.valueOf(Long.rotateLeft(state[i][j].longValue(), ROTATION_OFFSETS[i][j]));
            }
        }

        // χ step
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                state[i][j] = B[i][j].xor((B[(i + 1) % 5][j].not().and(B[(i + 2) % 5][j])));
            }
        }

        // ι step
        state[0][0] = state[0][0].xor(BigInteger.valueOf(round));
    }
}
