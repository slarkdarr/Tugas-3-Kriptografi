import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ECDSA {

    private static final BigInteger Gx = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger Gy = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger a = BigInteger.ZERO;

    public static KeyPair generateKeyPair() {
        BigInteger d = new BigInteger(n.bitLength(), new SecureRandom());
        while (d.equals(BigInteger.ZERO) || d.compareTo(n) >= 0) {
            d = new BigInteger(n.bitLength(), new SecureRandom());
        }
        BigInteger[] Q = pointMultiply(d, Gx, Gy);
        return new KeyPair(Q[0], Q[1], d);
    }

    public static Signature sign(byte[] message, BigInteger d) {
        BigInteger k, r;

        do {
            k = new BigInteger(n.bitLength(), new SecureRandom());
            while (k.equals(BigInteger.ZERO) || k.compareTo(n) >= 0) {
                k = new BigInteger(n.bitLength(), new SecureRandom());
            }

            BigInteger[] Q = pointMultiply(k, Gx, Gy);
            r = Q[0].mod(n);
        } while (r.equals(BigInteger.ZERO));

        BigInteger e = new BigInteger(Keccak256.hash(message));
        BigInteger s = (k.modInverse(n)).multiply(e.add(d.multiply(r))).mod(n);
        return new Signature(r, s);
    }

    public static boolean verify(byte[] message, BigInteger Qx, BigInteger Qy, Signature signature) {
        BigInteger e = new BigInteger(Keccak256.hash(message));
        BigInteger r = signature.getR();
        BigInteger s = signature.getS();
        BigInteger w = s.modInverse(n);
        BigInteger u1 = e.multiply(w).mod(n);
        BigInteger u2 = r.multiply(w).mod(n);

        BigInteger[] P = pointAdd(pointMultiply(u1, Gx, Gy), pointMultiply(u2, Qx, Qy));

        BigInteger x = P[0].mod(n);
        return x.equals(r);
    }

    private static BigInteger[] pointMultiply(BigInteger k, BigInteger x, BigInteger y) {
        if (k.equals(BigInteger.ZERO)) {
            return new BigInteger[] {BigInteger.ZERO, BigInteger.ZERO};
        }

        BigInteger[] Q = pointMultiply(k.divide(BigInteger.TWO), x, y);
        BigInteger[] P = pointAdd(Q, Q);

        if (k.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
            return pointAdd(P, new BigInteger[] { x, y });
        }
        return P;
    }

    private static BigInteger[] pointAdd(BigInteger[] P, BigInteger[] Q) {
        BigInteger x1 = P[0];
        BigInteger y1 = P[1];
        BigInteger x2 = Q[0];
        BigInteger y2 = Q[1];

        if (x1.equals(BigInteger.ZERO) && y1.equals(BigInteger.ZERO)) {
            return Q;
        }
        if (x2.equals(BigInteger.ZERO) && y2.equals(BigInteger.ZERO)) {
            return P;
        }

        if (x1.equals(x2) && y1.equals(y2)) {
            BigInteger m = (x1.pow(2).multiply(BigInteger.valueOf(3)).add(a)).multiply(y1.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p);
            BigInteger x3 = (m.pow(2)).subtract(x1.multiply(BigInteger.valueOf(2))).mod(p);
            BigInteger y3 = (m.multiply(x1.subtract(x3))).subtract(y1).mod(p);
            return new BigInteger[] {x3, y3};
        }

        BigInteger m = (y1.subtract(y2)).multiply(x1.subtract(x2).modInverse(p)).mod(p);
        BigInteger x3 = (m.pow(2)).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = (m.multiply(x1.subtract(x3))).subtract(y1).mod(p);
        return new BigInteger[] {x3, y3};
    }
}
