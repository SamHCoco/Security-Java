package security.rsa;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;

public class RSA {

    private HashMap<String ,BigInteger> publicKey;
    private HashMap<String, BigInteger> privateKey;
    private BigInteger totient;
    private BigInteger n;
    private BigInteger[] cipherText;

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
     * Encrypts plaintext passed as argument into cipher text using RSA
     * @param message The plain text message to be encrypted
     */
    public void encrypt(String message){
        if(this.isECoprime()){
            if(message.length() > 0){
                cipherText = new BigInteger[message.length()];
                String ascii = stringToAscii(message);

                if(ascii != null){
                    Scanner scanner = new Scanner(ascii);
                    int counter = 0;
                    while(scanner.hasNext()){
                        int character = Integer.valueOf(scanner.next());
                        cipherText[counter] = encrypt(character);
                        counter++;
                    }
                    System.out.println(Arrays.toString(cipherText)); // todo - remove
                }
            }
        }
    }


    /**
     * Encrypts an ascii code by applying A^e mod(n), where A = ascii code, e = public key, and n = p * q
     * @param asciiCode the ascii code to be encrypted
     * @return An encrypted ascii code as a BigInteger value
     */
    private BigInteger encrypt(int asciiCode){
        BigInteger bigAscii = BigInteger.valueOf(asciiCode);
        return bigAscii.modPow(publicKey.get("e"), publicKey.get("n")); // returns c = M^e mod(n)
    }

    /**
     * Decrypts cipher text, c, back to plain text, m, using private key d, via m = c^d mod(n).
     * @return Reverts the encrypted message stored by object as plain text (decrypted).
     */
    public String decrypt(){
        String plainText = "";
        if(cipherText != null){
            BigInteger d = privateKey.get("d");
            for(BigInteger cipherValue : cipherText){
                char character =  (char) cipherValue.modPow(d, n).intValue(); // m = c^d mod(n)
                plainText += String.valueOf(character);

            }
            System.out.println("DECRYPTED TEXT: " + plainText);
            return plainText;
        }
        return null;
    }


    /**
     * Determines whether the Greatest Common Divisor of totient Q(n) and e equals 1
     * (i.e. whether they are co-prime).
     * @return true if totient Q(n) and e are co-prime, false otherwise
     */
     public boolean isECoprime(){
        if(totient.gcd(n).equals(BigInteger.ONE)){
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
                if( i < message.length() - 1){
                    asciiFormat += String.valueOf((int) message.charAt(i)) + " ";
                } else {
                    asciiFormat += String.valueOf((int) message.charAt(i));
                }
            }
            return asciiFormat;
        }
        return null;
    }

}
