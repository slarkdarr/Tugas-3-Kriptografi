package com.fsck.k9.lib;


import java.math.BigInteger;

public class Signature {

    private final BigInteger r;
    private final BigInteger s;

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public BigInteger getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }

    @Override
    public String toString() {
        return "Signature{" +
                "r=" + r +
                ", s=" + s +
                '}';
    }
}
