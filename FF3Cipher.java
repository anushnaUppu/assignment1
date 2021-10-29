
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class FF3Cipher {

    public static int BLOCK_SIZE =   16;     
    public static int TWEAK_LEN =    8;      
    public static int HALF_TWEAK_LEN = TWEAK_LEN/2;
    public static int MAX_RADIX =    36;      

    private final int radix = 10;
    private byte[] tweakBytes;
    private final int minLen;
    private final int maxLen;
    private final Cipher desCipher;
    
    public FF3Cipher(String key, String tweak) {
        byte[] keyBytes = hexStringToByteArray(key);
        this.minLen = (int) Math.ceil(Math.log(1000000) / Math.log(radix));

        this.maxLen = (int) (2 * Math.floor(Math.log(Math.pow(2,96))/Math.log(radix)));

        if ((this.minLen < 2) || (this.maxLen < this.minLen)) {
            throw new IllegalArgumentException ("minLen or maxLen invalid, adjust your radix");
        }

        this.tweakBytes = hexStringToByteArray(tweak);

        try {
            reverseBytes(keyBytes);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
            desCipher = Cipher.getInstance("DES/ECB/NoPadding");
            desCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public String encrypt(String plaintext) throws BadPaddingException, IllegalBlockSizeException {
        int n = plaintext.length();
        validate(n,plaintext);
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;
        String A = plaintext.substring(0,u);
        String B = plaintext.substring(u);
        byte[] Tl = Arrays.copyOf(this.tweakBytes, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(this.tweakBytes, HALF_TWEAK_LEN, TWEAK_LEN);
        byte[] P;
        for (byte i = 0; i < 8; ++ i) {
            int m;
            BigInteger c;
            byte[] W;
            if (i % 2 == 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }
            P = getPValue( i, this.radix, W, B);
            reverseBytes(P);
            byte[] S = this.desCipher.doFinal(P);
            reverseBytes(S);
            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);
            try {
                c = new BigInteger(reverseString(A), this.radix);
            } catch (NumberFormatException ex) {
                throw new RuntimeException("string A is not within base/radix");
            }
            c = c.add(y);
            c = c.mod(BigInteger.valueOf(this.radix).pow(m));
            String C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length());
            A = B;
            B = C;
        }
        
        return A+B;
    }

    public String decrypt(String ciphertext, String tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = hexStringToByteArray(tweak);
        return decrypt(ciphertext);
    }

    public String decrypt(String ciphertext) throws BadPaddingException, IllegalBlockSizeException {
        int n = ciphertext.length(); 
        validate(n,ciphertext);
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;
        String A = ciphertext.substring(0,u);
        String B = ciphertext.substring(u);
        byte[] Tl = Arrays.copyOf(this.tweakBytes, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(this.tweakBytes, HALF_TWEAK_LEN, TWEAK_LEN);
        byte[] P;
        for (byte i = (byte) (7); i >= 0; --i) {
            int m;
            BigInteger c;
            byte[] W;
            if (i % 2 == 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }
            P = getPValue( i, this.radix, W, A);
            reverseBytes(P);
            byte[] S = this.desCipher.doFinal(P);
            reverseBytes(S);
            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);
            try {
                c = new BigInteger(reverseString(B), this.radix);
            } catch (NumberFormatException ex) {
                throw new RuntimeException("string B is not within base/radix");
            }
            c = c.subtract(y);
            c = c.mod(BigInteger.valueOf(this.radix).pow(m));
            String C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length());
            B = A;
            A = C;
        }
        return A+B;
    }

    protected void validate(int n,String text) {
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw new IllegalArgumentException(String.format("message length %d is not within min %d and max %d bounds",
                    n, this.minLen, this.maxLen));
        }
        if (this.tweakBytes.length != TWEAK_LEN){
            throw new IllegalArgumentException(String.format("tweak length %d is invalid: tweak must be 8 bytes, or 64 bits",
                    this.tweakBytes.length * 2));
        }
        try {
            new BigInteger(text, this.radix);
        } catch (NumberFormatException ex) {
            throw new NumberFormatException(String.format("The given text is not supported in the current radix %d", this.radix));
        }
    }
    protected static byte[] getPValue(int i, int radix, byte[] W, String B) {

        byte[] P = new byte[BLOCK_SIZE];
        P[0] = W[0];
        P[1] = W[1];
        P[2] = W[2];
        P[3] = (byte) (W[3] ^ i);
        B = reverseString(B);
        byte[] bBytes = new BigInteger(B, radix).toByteArray();
        return P;
    }

    protected static String reverseString(String s) {
        return new StringBuilder(s).reverse().toString();
    }
    protected void reverseBytes(byte[] b) {
        for(int i=0; i<b.length/2; i++){
            byte temp = b[i];
            b[i] = b[b.length -i -1];
            b[b.length -i -1] = temp;
        }
    }

    protected static byte[] hexStringToByteArray(String s) {
        byte[] data = new byte[s.length()/2];
        for(int i=0;i < s.length();i+=2) {
            data[i/2] = (Integer.decode("0x"+s.charAt(i)+s.charAt(i+1))).byteValue();
        }
        return data;
    }

    protected static String byteArrayToHexString(byte[] byteArray){

        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            String aByte = String.format("%02X", b);
            sb.append(aByte);
        }
        return sb.toString();
    }
    protected static String byteArrayToIntString(byte[] byteArray){

        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (byte b : byteArray) {
            String aByte = String.format("%d ", ((int) b) & 0xFF);
            sb.append(aByte);
        }
        sb.append(']');
        return sb.toString();
    }

}
