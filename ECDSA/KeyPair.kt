import java.math.BigInteger

class KeyPair(val qx: BigInteger, val qy: BigInteger, val d: BigInteger) {

    override fun toString(): String {
        return "KeyPair{" +
                "Qx=" + qx +
                ", Qy=" + qy +
                ", d=" + d +
                '}'
    }
}
