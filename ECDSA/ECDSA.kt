import java.math.BigInteger
import java.security.SecureRandom

object ECDSA {

    private val Gx = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    private val Gy = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    private val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val a = BigInteger.ZERO

    fun generateKeyPair(): KeyPair {
        var d = BigInteger(n.bitLength(), SecureRandom())
        while (d == BigInteger.ZERO || d.compareTo(n) >= 0) {
            d = BigInteger(n.bitLength(), SecureRandom())
        }
        val Q = pointMultiply(d, Gx, Gy)
        return KeyPair(Q[0], Q[1], d)
    }

    fun sign(message: ByteArray?, d: BigInteger): Signature {
        var k: BigInteger
        var r: BigInteger
        do {
            k = BigInteger(n.bitLength(), SecureRandom())
            while (k == BigInteger.ZERO || k.compareTo(n) >= 0) {
                k = BigInteger(n.bitLength(), SecureRandom())
            }
            val Q = pointMultiply(k, Gx, Gy)
            r = Q[0].mod(n)
        } while (r == BigInteger.ZERO)
        val e = BigInteger(message?.let { Keccak256.hash(it) })
        val s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n)
        return Signature(r, s)
    }

    fun verify(message: ByteArray?, Qx: BigInteger, Qy: BigInteger, signature: Signature): Boolean {
        val e = BigInteger(message?.let { Keccak256.hash(it) })
        val r = signature.r
        val s = signature.s
        val w = s.modInverse(n)
        val u1 = e.multiply(w).mod(n)
        val u2 = r.multiply(w).mod(n)
        val P = pointAdd(pointMultiply(u1, Gx, Gy), pointMultiply(u2, Qx, Qy))
        val x = P[0].mod(n)
        return x == r
    }

    private fun pointMultiply(k: BigInteger, x: BigInteger, y: BigInteger): Array<BigInteger> {
        if (k == BigInteger.ZERO) {
            return arrayOf(BigInteger.ZERO, BigInteger.ZERO)
        }
        val Q = pointMultiply(k.divide(BigInteger.TWO), x, y)
        val P = pointAdd(Q, Q)
        return if (k.mod(BigInteger.TWO) == BigInteger.ONE) {
            pointAdd(P, arrayOf(x, y))
        } else P
    }

    private fun pointAdd(P: Array<BigInteger>, Q: Array<BigInteger>): Array<BigInteger> {
        val x1 = P[0]
        val y1 = P[1]
        val x2 = Q[0]
        val y2 = Q[1]
        if (x1 == BigInteger.ZERO && y1 == BigInteger.ZERO) {
            return Q
        }
        if (x2 == BigInteger.ZERO && y2 == BigInteger.ZERO) {
            return P
        }
        if (x1 == x2 && y1 == y2) {
            val m = x1.pow(2).multiply(BigInteger.valueOf(3)).add(a).multiply(y1.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p)
            val x3 = m.pow(2).subtract(x1.multiply(BigInteger.valueOf(2))).mod(p)
            val y3 = m.multiply(x1.subtract(x3)).subtract(y1).mod(p)
            return arrayOf(x3, y3)
        }
        val m = y1.subtract(y2).multiply(x1.subtract(x2).modInverse(p)).mod(p)
        val x3 = m.pow(2).subtract(x1).subtract(x2).mod(p)
        val y3 = m.multiply(x1.subtract(x3)).subtract(y1).mod(p)
        return arrayOf(x3, y3)
    }
}
