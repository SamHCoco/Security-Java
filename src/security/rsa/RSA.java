package security.rsa;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;

public class RSA {

    private HashMap<String ,BigInteger> publicKey;
    private HashMap<String, BigInteger> privateKey;
    private BigInteger totient;
    private BigInteger n;

    public RSA(int keyBits){
        if(keyBits >= 1024){
            publicKey = new HashMap<>();
            privateKey = new HashMap<>();

            BigInteger p = BigInteger.probablePrime(keyBits/2, new Random());
            BigInteger q = BigInteger.probablePrime(keyBits/2, new Random());

            BigInteger pMinus1 = p.subtract(BigInteger.ONE);
            BigInteger qMinus1 = q.subtract(BigInteger.ONE);

            BigInteger e = BigInteger.valueOf(65_537);
            n = p.multiply(q);
            totient = pMinus1.multiply(qMinus1);

            publicKey.put("e", e);
            publicKey.put("n", n);
            privateKey.put("d", e.modInverse(totient));
            privateKey.put("n", n);
        }
    }

    /**
     * Determines whether the Greatest Common Divisor of totient Q(n) and e equals 1
     * (i.e. whether they are co-prime).
     * @return true if totient Q(n) and e are co-prime, false otherwise
     */
    private boolean isECoprime(){
        if(totient.gcd(n) == BigInteger.ONE){
            return true;
        } else {
            return false;
        }
    }

    /**
     * Converts a string to its ascii code representation.
     * @param message The string to be converted
     * @return the passed string in its ascii code form, or null if the string has length = 0
     */
    public static String stringToAscii(String message){
        if(message.length() > 0){
            String asciiFormat = "";
            for(int i = 0; i < message.length(); i++){
                asciiFormat += String.valueOf((int) message.charAt(i)) + " ";
            }
            return asciiFormat;
        }
        return null;
    }

}
