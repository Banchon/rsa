package rsa;

import java.math.BigInteger;

public class RSACompleteKey extends RSAPrivateKey 
{   
    /** The public exponent. */
    private BigInteger e;
    
    /** The larger prime factor of the modulus. */
    private BigInteger p;

    /** The smaller prime factor of the modulus. */
    private BigInteger q;
    
    /** The Euler number of the modulus. */
    private BigInteger phi;
     
    
    /** Default constructor. */
    public RSACompleteKey() {
        super(null, null);
        setPubExp(null);
        setPrimes(null, null);
        return;
    }
    
    /** Main constructor. */
    public RSACompleteKey(BigInteger prime1,
                          BigInteger prime2,
                          BigInteger modulus,
                          BigInteger pubExp,
                          BigInteger priExp
                         ) {
        super(modulus, priExp);
        setPubExp(pubExp);
        setPrimes(prime1, prime2);    
        return;
    }
    

    
    /** Computes the Euler function of modulus. */
    protected void computePhi() {
        phi = pMinusOne().multiply(qMinusOne());
    }
       
    /** Returns phi. */
    public BigInteger getPhi() {
        return phi;
    }
    
    /** Returns the larger prime factor. */
    public BigInteger getPrimeOne() {
        return p;
    }
        
    /** Returns the smaller prime factor. */
    public BigInteger getPrimeTwo() {
        return q;
    }
        
    /** Returns the public exponent. */
    public BigInteger getPubExp() {
        return e;
    }
    
    /** Returns true when key is valid. */
    public boolean isValid() {
        if (noValuesNull() && isPrime(p) && isPrime(q)) {
            computePhi();
            return p.multiply(q).equals(getModulus()) &&
                   e.compareTo(THREE) >= 0 &&
                   e.compareTo(getModulus()) < 0 &&
                   e.gcd(phi).equals(ONE) &&
                   getPriExp().compareTo(getModulus()) < 0 &&
                   getPriExp().equals(e.modInverse(phi));
        } else {
            return false;
        }
    }
    
    /** Returns true when no fields are null. */
    private boolean noValuesNull() {
        return !(isNull(p) || isNull(q) || isNull(getModulus()) || 
                 isNull(e) || isNull(getPriExp()));
    }
    
    /** Returns p minus one. */
    protected BigInteger pMinusOne() {
        if (isNull(p)) {
            return null;
        } else {
            return p.subtract(ONE);
        }
    }
    
    /** Returns q minus one. */
    protected BigInteger qMinusOne() {
        if (isNull(q)) {
            return null;
        } else {
            return q.subtract(ONE);
        }
    }
       
    /** Sets phi. */
    public void setPhi(BigInteger phi) {
        this.phi = weedOut(phi);
    }
    
    /** Sets the prime factors. */
    public void setPrimes(BigInteger prime1, BigInteger prime2) {
        if (isNull(prime1 = weedOut(prime1)) || isNull(prime2 = weedOut(prime2))) {
            return;
        } else {
            if (isPositive(prime1.subtract(prime2))) {
                p = prime1;
                q = prime2;
            } else if (isPositive(prime2.subtract(prime1))) {
                p = prime2;
                q = prime1;
            } else {
                return;
            }
        }
        return;
    }
    
    /** Sets the public exponent. */
    public void setPubExp(BigInteger pubExp) {
        e = weedOut(pubExp);
        return;
    }    
}
