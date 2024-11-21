import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSA {
    private BigInteger n, d, e;
    private int bitlen = 1048; // key size in bits

    // Constructor to generate public and private keys
    public RSA() {
        // Generate prime numbers p and q
        BigInteger p = BigInteger.probablePrime(bitlen / 2, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(bitlen / 2, new SecureRandom());

        // Compute n = p * q
        n = p.multiply(q);

        // Compute Euler's totient function phi(n) = (p - 1) * (q - 1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Select e, the public exponent. It is common to choose 65537
        e = new BigInteger("65537");

        // Compute d, the modular multiplicative inverse of e modulo phi(n)
        d = e.modInverse(phi);
    }

    // Encrypt a message using the public key
    public BigInteger encrypt(String message) {
        // Convert the message to a BigInteger
        BigInteger messageBigInt = new BigInteger(message.getBytes());

        // Encrypt using c ≡ m^e (mod n)
        return messageBigInt.modPow(e, n);
    }

    // Decrypt a message using the private key
    public String decrypt(BigInteger ciphertext) {
        // Decrypt using m ≡ c^d (mod n)
        BigInteger messageBigInt = ciphertext.modPow(d, n);

        // Convert the BigInteger back to a string
        return new String(messageBigInt.toByteArray());
    }

    // Get the public key
    public BigInteger getPublicKey() {
        return e;
    }

    // Get the modulus n
    public BigInteger getModulus() {
        return n;
    }

    public static void main(String[] args) {
        // Create RSA object to generate keys
        RSA rsa = new RSA();
        
        // Create a Scanner object to take input from the user
        Scanner scanner = new Scanner(System.in);

        // Prompt the user to enter a message to encrypt
        System.out.print("Enter the message to encrypt: ");
        String message = scanner.nextLine();

        // Encrypt the message
        System.out.println("Original Message: " + message);
        BigInteger encryptedMessage = rsa.encrypt(message);
        System.out.println("Encrypted Message (in BigInteger): " + encryptedMessage);

        // Decrypt the message
        String decryptedMessage = rsa.decrypt(encryptedMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);

        // Close the scanner
        scanner.close();
    }
}
