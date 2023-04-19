import java.math.BigInteger

class Signature(val r: BigInteger, val s: BigInteger) {

    override fun toString(): String {
        return "Signature{" +
                "r=" + r +
                ", s=" + s +
                '}'
    }
}
