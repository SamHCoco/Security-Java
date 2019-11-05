package security.unittesting;

import org.junit.Test;
import security.rsa.RSA;

import static org.junit.Assert.*;
import static security.rsa.RSA.stringToAscii;


public class RSATest {

    @Test
    public void stringToAsciiTest(){
        String test1 = "Hello";
        String test2 = "This is an ascii test test.";
        String test3 = "3.14ZQxY'£*&()^%$!-+][{};:'#?,<>.|/";
        String test1Expected = "72 101 108 108 111";
        String test2Expected = "84 104 105 115 32 105 115 32 97 110 32 97 115 " +
                               "99 105 105 32 116 101 115 116 32 116 101 115 116 46";
        String test3Expected = "32 51 46 49 52 90 81 120 89 39 194 163 42 38 40 41 94 37 " +
                               "36 33 45 43 93 91 123 125 59 58 39 35 63 44 60 62 46 124 47";
        assertEquals(stringToAscii(test1), test1Expected);
        assertEquals(stringToAscii(test2), test2Expected);
        assertEquals(stringToAscii(test3), test3Expected);
    }
}
