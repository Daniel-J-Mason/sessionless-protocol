package com.allthing.libs.sessionless;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.UUID;

/**
 * Sessionless is an authentication protocol that uses the cryptography employed by
 * Bitcoin and Ethereum to authenticate messages sent between a client and a server.
 */
public class Sessionless {
    
    /**
     * Generates a new set of keys.
     *
     * @return An array of Strings where the first element is the private key and the second element is the public key.
     */
    public static String[] generateKeys() {
        KeyPairGenerator generator;
        Security.addProvider(new BouncyCastleProvider());
        ECNamedCurveParameterSpec ecNamedCurveParameterSpec =
                ECNamedCurveTable.getParameterSpec("secp256k1");
        
        try {
            generator = KeyPairGenerator.getInstance("ECDSA", "BC");
            generator.initialize(ecNamedCurveParameterSpec, new SecureRandom());
            
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        
        KeyPair keyPair = generator.generateKeyPair();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        
        String privateKeyHex = extractPrivateKeyHex(ecPrivateKey);
        String publicKeyHex = extractPublicKeyHex(ecPublicKey);
        
        return new String[]{privateKeyHex, publicKeyHex};
    }
    
    /**
     * Signs a message using provided private key.
     *
     * @return Hex encoded signature.
     */
    public static String sign(String privateKey, String message) {
        ECNamedCurveParameterSpec ecNamedCurveParameterSpec =
                ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain =
                new ECDomainParameters(
                        ecNamedCurveParameterSpec.getCurve(),
                        ecNamedCurveParameterSpec.getG(),
                        ecNamedCurveParameterSpec.getN(),
                        ecNamedCurveParameterSpec.getH());
        
        BigInteger privateKeyFormatted = new BigInteger(privateKey, 16);
        
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyFormatted, domain);
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, privateKeyParameters);
        
        byte[] messageHash = keccakMessageHash(message);
        BigInteger[] signature = signer.generateSignature(messageHash);
        
        return String.format("%s%s", bigIntegerHexToString(signature[0]), bigIntegerHexToString(signature[1]));
    }
    
    /**
     * Verifies a signature using provided public key and message.
     *
     * @return True if signature is valid, else false.
     */
    public static boolean verifySignature(String publicKey, String signature, String message) {
        BigInteger publicKeyFormatted = new BigInteger(publicKey, 16);
        ECNamedCurveParameterSpec ecNamedCurveParameterSpec =
                ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain =
                new ECDomainParameters(
                        ecNamedCurveParameterSpec.getCurve(),
                        ecNamedCurveParameterSpec.getG(),
                        ecNamedCurveParameterSpec.getN(),
                        ecNamedCurveParameterSpec.getH());
        org.bouncycastle.math.ec.ECPoint publicKeyPoint = ecNamedCurveParameterSpec.getCurve().decodePoint(publicKeyFormatted.toByteArray());
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(publicKeyPoint, domain);
        
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKeyParameters);
        
        MessageDigest digest = new Keccak.Digest256();
        byte[] messageHash = digest.digest(message.getBytes());
        
        return signer.verifySignature(messageHash, new BigInteger(signature.substring(0, 64), 16), new BigInteger(signature.substring(64, 128), 16));
    }
    
    /**
     * Associates two pairs of public keys and signatures with two messages.
     *
     * @return True if both signatures are valid, else false.
     */
    public static boolean associate(String primaryPublicKey, String primarySignature, String primaryMessage,
                                    String secondaryPublicKey, String secondarySignature, String secondaryMessage) {
        return verifySignature(primaryPublicKey, primarySignature, primaryMessage)
                && verifySignature(secondaryPublicKey, secondarySignature, secondaryMessage);
    }
    
    /**
     * Generates a random UUID.
     *
     * @return Generated UUID.
     */
    public static UUID generateUuid() {
        return UUID.randomUUID();
    }
    
    private static String extractPrivateKeyHex(ECPrivateKey ecPrivateKey) {
        BigInteger privateKeyBigInt = ecPrivateKey.getS();
        return privateKeyBigInt.toString(16);
    }
    
    private static String extractPublicKeyHex(ECPublicKey ecPublicKey) {
        
        ECPoint ecPoint = ecPublicKey.getW();
        BigInteger rawX = ecPoint.getAffineX();
        BigInteger rawY = ecPoint.getAffineY();
        
        //Add compression prefix based on sign
        boolean yIsEven = rawY.mod(new BigInteger("2")).equals(BigInteger.ZERO);
        rawX = rawX.abs();
        String prefix = yIsEven ? "02" : "03";
        
        //Ensure stripped 0's are sign only
        String publicKeyHex = bigIntegerHexToString(rawX);
        publicKeyHex = prefix + publicKeyHex;
        
        return publicKeyHex;
    }
    
    private static byte[] keccakMessageHash(String message) {
        MessageDigest digest = new Keccak.Digest256();
        return digest.digest(message.getBytes());
    }

    private static String bigIntegerHexToString(BigInteger bigIntegerHex) {
        String hex = bigIntegerHex.toString(16);
        hex = StringUtils.leftPad(hex, 64, '0');
        return hex;
    }
}
