package virtual_private_network;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Crypto {
	protected static final int MIN_SECRET_VALUE = 100;
	
	protected static final String ALGORITHM_ENCRYPTION = "AES";
	protected static final String ALGORITHM_HASH = "MD5";
	protected static final String ALGORITHM_SIGNING = "RSA";

	protected BigInteger calculateSharedDH(BigInteger a) {
		BigInteger p = VirtualPrivateNetwork.getP();
		BigInteger g = VirtualPrivateNetwork.getG();
		return g.modPow(a, p);
	}
	
	protected BigInteger calculateSecretDH(BigInteger sharedDH, BigInteger a) {
		BigInteger p = VirtualPrivateNetwork.getP();
		return sharedDH.modPow(a, p);
	}

	
	protected String encryptWithRSA(String plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] ciphertext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_SIGNING);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		ciphertext = cipher.doFinal(plaintext.getBytes());
		
		return DatatypeConverter.printBase64Binary(ciphertext);
	}
	
	protected String decryptWithRSA(String ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] plaintext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_SIGNING);
		cipher.init(Cipher.DECRYPT_MODE, key);
		plaintext = cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext));
		
		return new String(plaintext);
	}
	
	protected String encryptWithAES(String plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] ciphertext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_ENCRYPTION);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		ciphertext = cipher.doFinal(plaintext.getBytes());
		
		return DatatypeConverter.printBase64Binary(ciphertext);
	}
	
	protected String decryptWithAES(String ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] plaintext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_ENCRYPTION);
		cipher.init(Cipher.DECRYPT_MODE, key);
		plaintext = cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext));
		
		return new String(plaintext);
	}
	
	/**
	 * Key is encrypted using server's public key, so use protected key to decrypt
	 * This step verifies the identity of the server
	 * @param encryptedKey
	 * @return
	 */
	protected byte[] extractAuthenticationEncryptionKey(String encryptedKey, PrivateKey pvKey) {		
		String enKeyString;
		try {
			enKeyString = decryptWithRSA(encryptedKey, pvKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			log("Error with decrypting message with protected key");
			log(e.getMessage());
			return null;
		}
		
		byte[] enKeyBytes = DatatypeConverter.parseBase64Binary(enKeyString);			
		log("Encryption key: " + enKeyString);
		
		waitForCont();		
		return enKeyBytes;
	}
	
	/**
	 * First decrypts the message using the encryption key found before
	 * Then decrypts the message with the client's public key
	 * This step verifies the client's identity
	 * @param response
	 * @param enKeyBytes
	 * @return
	 */
	protected String decryptAuthenticationMessage(String response, byte[] enKeyBytes, PublicKey pbKey) {
		String message;
		try {
			message = decryptWithAES(response, generateSecretKey(enKeyBytes));
			message = decryptWithRSA(message, pbKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			log("Error with decrypting authentication message with public key and authentication encryption key");
			log(e.getMessage());
			return null;
		}
		
		log("Decrypted message: " + message);
		log("Current timestamp: " + System.currentTimeMillis());
		
		waitForCont();
		return message;
	}
	
	/**
	 * Extracts the shared DH and creates a secret DH to use as a session key for encrypting and decrypting data transferred
	 * This steps ensures confidentiality of data transfered because the secret DH is forgotten after this session
	 * @param response
	 * @return
	 */
	protected SecretKey extractMessageEncryptionKey(String response, BigInteger secretValue) {
		SecretKey messageKey;
		try {
			BigInteger secretDH = calculateSecretDH(new BigInteger(response), secretValue);
			log("Secret DH: " + secretDH.toString());
			messageKey = generateMessageKey(secretDH);
		} catch (NoSuchAlgorithmException e) {
			log("Extracting message encryption key from given shared shared DH failed");
			log(e.getMessage());
			return null;
		}
		
		log("Message encryption key: " + DatatypeConverter.printBase64Binary(messageKey.getEncoded()));
		
		waitForCont();
		return messageKey;		
	}
	
	/**
	 * Encrypt the authentication encryption key with the client's public key
	 * This step serves to authenticate the client because only he or she can decrypt this key
	 * 
	 * @param enKey
	 * @return
	 */
	protected String encryptAuthenticationEncryptionKey(SecretKey enKey, PublicKey pbKey) {
		String encryptedKey;
		try {
			log('\n' + "Encrypting AES key..." + '\n');
			
			String encryptionKey = DatatypeConverter.printBase64Binary(enKey.getEncoded());
			log("Authentication Encryption key: " + encryptionKey);
			encryptedKey = encryptWithRSA(encryptionKey, pbKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			log("Encrypting encryption key with public key failed");
			log(e.getMessage());
			return null;
		}
		
		log("Encrypted authentication encryption Key: " + encryptedKey);
		
		waitForCont();
		return encryptedKey;
	}
	
	/**
	 * Signs the timestamp and shared DH
	 * This steps lets the client verify the server's identity
	 * @return
	 */
	protected String signAuthenticationMessage(BigInteger secretValue, PrivateKey pvKey) {		
		String signedMsg;
		try {
			long timestamp = System.currentTimeMillis();
			BigInteger sharedDH = calculateSharedDH(secretValue);
				
			log("Encrypting timestamp (" + timestamp + ") and shared DH (" + sharedDH.toString() + ") for authentication...");
			signedMsg = encryptWithRSA(Long.toString(timestamp) + ";" + sharedDH.toString(), pvKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			log("Signing timestamp and shared DH failed");
			log(e.getMessage());
			return null;
		}
		
		log("Signed timestap and shared DH: " + signedMsg);
		
		waitForCont();
		return signedMsg;
	}
	
	/**
	 * Encrypts the authentication message with the key encrypted by the client's public key
	 * This step verifies client's indentity
	 * @param message
	 * @param enKey
	 * @return
	 */
	protected String encryptAuthenticationMessage(String message, SecretKey enKey) {
		String encryptedMsg;
		try {
			log('\n' + "Encrypting message with AES..." + '\n');
			encryptedMsg = encryptWithAES(message, enKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			log("Encrypting authentication message failed");
			log(e.getMessage());
			return null;
		}
		
		log("Final authentication message:" + encryptedMsg);
		
		waitForCont();
		return encryptedMsg;
	}
	
	protected SecretKey generateMessageKey(BigInteger secretDH) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(ALGORITHM_HASH);
		byte[] msgKeyByte = md.digest(secretDH.toByteArray());
		return new SecretKeySpec(msgKeyByte, 0, msgKeyByte.length, ALGORITHM_ENCRYPTION);
	}
	
	protected SecretKey generateSecretKey(byte[] keyBytes) {
		return new SecretKeySpec(keyBytes, 0, keyBytes.length, ALGORITHM_ENCRYPTION);
	}
	
	protected PrivateKey generatePrivateKey(String protectedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM_SIGNING);
		
		byte[] encodedPv = DatatypeConverter.parseBase64Binary(protectedKey);
		PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(encodedPv);
		return kf.generatePrivate(keySpecPv);
	}
	
	protected PublicKey generatePublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM_SIGNING);
		
		byte[] encodedPb = DatatypeConverter.parseBase64Binary(publicKey);
		X509EncodedKeySpec keySpecPb = new X509EncodedKeySpec(encodedPb);
		return kf.generatePublic(keySpecPb);	
	}
	
	protected SecretKey generateSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_ENCRYPTION);
		keyGen.init(128);
		return keyGen.generateKey();
	}
	
	protected void log(String msg) {
		VirtualPrivateNetwork.log(msg);
	}

	protected void waitForCont() {
		while(!VirtualPrivateNetwork.getContinue()) {
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				break;
			}
		}
		VirtualPrivateNetwork.setContinue(false);
	}
}
