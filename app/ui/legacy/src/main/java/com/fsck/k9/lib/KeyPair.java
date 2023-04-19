package com.fsck.k9.lib;


import java.math.BigInteger;

public class KeyPair {

    private final BigInteger Qx;
    private final BigInteger Qy;
    private final BigInteger d;

    public KeyPair(BigInteger Qx, BigInteger Qy, BigInteger d) {
        this.Qx = Qx;
        this.Qy = Qy;
        this.d = d;
    }

    public BigInteger getQx() {
        return Qx;
    }

    public BigInteger getQy() {
        return Qy;
    }

    public BigInteger getD() {
        return d;
    }

    @Override
    public String toString() {
        return "KeyPair{" +
                "Qx=" + Qx +
                ", Qy=" + Qy +
                ", d=" + d +
                '}';
    }
}
