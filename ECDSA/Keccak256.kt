import java.math.BigInteger
import java.util.*

/**
 * This class implements Keccak hash function based on the specifications provided at
 * https://keccak.team/keccak_specs_summary.html
 */
object Keccak256 {

    private const val R = 1088
    private const val C = 1600 - R
    private const val BLOCK_SIZE = C / 8
    private const val OUTPUT_SIZE = 32

    private val ROUND_CONSTANTS = longArrayOf(
            0x0000000000000001L, 0x0000000000008082L, -0x7fffffffffff7f76L, -0x7fffffff7fff8000L,
            0x000000000000808bL, 0x0000000080000001L, -0x7fffffff7fff7f7fL, -0x7fffffffffff7ff7L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, -0x7fffffffffffff75L, -0x7fffffffffff7f77L, -0x7fffffffffff7ffdL,
            -0x7fffffffffff7ffeL, -0x7fffffffffffff80L, 0x000000000000800aL, -0x7fffffff7ffffff6L,
            -0x7fffffff7fff7f7fL, -0x7fffffffffff7f80L, 0x0000000080000001L, -0x7fffffff7fff7ff8L
    )

    private val ROTATION_OFFSETS = arrayOf(intArrayOf(0, 1, 2, 3, 4), intArrayOf(0, 1, 2, 3, 4), intArrayOf(0, 1, 2, 3, 4), intArrayOf(0, 1, 2, 3, 4), intArrayOf(0, 1, 2, 3, 4))

    fun hash(message: ByteArray): ByteArray {
        val state = initializeState()
        val paddedMessage = pad(message)
        val blockCount = paddedMessage.size / BLOCK_SIZE
        for (i in 0 until blockCount) {
            absorb(state, paddedMessage, i * BLOCK_SIZE)
            keccak(state)
        }
        val hash = ByteArray(OUTPUT_SIZE)
        for (i in 0 until OUTPUT_SIZE) {
            squeeze(hash, state)
            keccak(state)
        }
        return hash
    }

    private fun initializeState(): Array<Array<BigInteger?>> {
        val state = Array(5) { arrayOfNulls<BigInteger>(5) }
        for (i in 0..4) {
            Arrays.fill(state[i], BigInteger.ZERO)
        }
        return state
    }

    private fun pad(message: ByteArray): ByteArray {
        val length = message.size
        if (length % BLOCK_SIZE == 0) {
            return message
        }
        val paddedLength = (length / BLOCK_SIZE + 1) * BLOCK_SIZE
        val paddedMessage = ByteArray(paddedLength)
        System.arraycopy(message, 0, paddedMessage, 0, length)
        paddedMessage[length] = 0x01.toByte()
        paddedMessage[paddedLength - 1] = (paddedMessage[paddedLength - 1].toInt() or 0x80.toByte().toInt()).toByte()
        return paddedMessage
    }

    private fun absorb(state: Array<Array<BigInteger?>>, message: ByteArray, offset: Int) {
        for (i in 0..4) {
            for (j in 0..4) {
                val index = j * 5 + i
                val bytes = Arrays.copyOfRange(message, offset + index, offset + index + 8)
                state[i][j] = state[i][j]!!.xor(BigInteger(1, bytes))
            }
        }
    }

    private fun squeeze(hash: ByteArray, state: Array<Array<BigInteger?>>) {
        for (i in 0..4) {
            for (j in 0..4) {
                val index = j * 5 + i
                var bytes = state[i][j]!!.toByteArray()
                val length = bytes.size
                if (bytes.size < 8) {
                    val paddedBytes = ByteArray(8)
                    System.arraycopy(bytes, 0, paddedBytes, 8 - length, length)
                    bytes = paddedBytes
                }
                System.arraycopy(bytes, 0, hash, index, 8)
            }
        }
    }

    private fun keccak(state: Array<Array<BigInteger?>>) {
        for (round in ROUND_CONSTANTS) {
            keccakF(state, round)
        }
    }

    private fun keccakF(state: Array<Array<BigInteger?>>, round: Long) {
        val C = arrayOfNulls<BigInteger>(5)
        val D = arrayOfNulls<BigInteger>(5)

        // 0 step
        for (i in 0..4) {
            C[i] = state[i][0]!!.xor(state[i][1]).xor(state[i][2]).xor(state[i][3]).xor(state[i][4])
        }
        for (i in 0..4) {
            D[i] = C[(i + 4) % 5]!!.xor(BigInteger.valueOf(java.lang.Long.rotateLeft(C[(i + 1) % 5]!!.toLong(), 1)))
        }
        for (i in 0..4) {
            for (j in 0..4) {
                state[i][j] = state[i][j]!!.xor(D[i])
            }
        }
        val B = Array(5) { arrayOfNulls<BigInteger>(5) }

        // ρ and π step
        for (i in 0..4) {
            for (j in 0..4) {
                B[j][(2 * i + 3 * j) % 5] = BigInteger.valueOf(java.lang.Long.rotateLeft(state[i][j]!!.toLong(), ROTATION_OFFSETS[i][j]))
            }
        }

        // χ step
        for (i in 0..4) {
            for (j in 0..4) {
                state[i][j] = B[i][j]!!.xor(B[(i + 1) % 5][j]!!.not().and(B[(i + 2) % 5][j]))
            }
        }

        // ι step
        state[0][0] = state[0][0]!!.xor(BigInteger.valueOf(round))
    }
}
