package virtual_private_network;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
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
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Crypto {
	protected static final int MIN_SECRET_VALUE = 100;
	
	protected static final String DIVIDER = ";";
	
	protected static final String ALGORITHM_ENCRYPTION = "AES";
	protected static final String ALGORITHM_HASH = "MD5";
	protected static final String ALGORITHM_MAC = "HmacMD5";
	protected static final String ALGORITHM_SIGNING = "RSA";
	
	//secret value to use in DH exchange
	protected BigInteger n;
	
	//used to encrypt messages sent after communication established
	protected SecretKey msgKey;
	protected BufferedReader in;
	protected DataOutputStream out;
	
	/**
	 * Calculates the shared DH value for DH exchange
	 * @return g^n mod p
	 */
	protected BigInteger calculateSharedDH() {
		BigInteger p = VirtualPrivateNetwork.getP();
		BigInteger g = VirtualPrivateNetwork.getG();
		return g.modPow(n, p);
	}
	
	/**
	 * Calculates the secret DH value used for message encryption
	 * @return g^(ab) mod p
	 */
	protected BigInteger calculateSecretDH(BigInteger sharedDH) {
		BigInteger p = VirtualPrivateNetwork.getP();
		return sharedDH.modPow(n, p);
	}

	/**
	 * Encrypt with a private or public key using RSA algorithm
	 * @param plaintext - text to encrypt
	 * @param key - public/private key
	 * @return ciphertext
	 */
	protected String encryptWithRSA(String plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] ciphertext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_SIGNING);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		ciphertext = cipher.doFinal(plaintext.getBytes());
		
		return DatatypeConverter.printBase64Binary(ciphertext);
	}
	
	/**
	 * Decrypt with a private or public key using RSA algorithm
	 * @param ciphertext - text to decrypt
	 * @param key - public/private key
	 * @return plaintext
	 */
	protected String decryptWithRSA(String ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] plaintext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_SIGNING);
		cipher.init(Cipher.DECRYPT_MODE, key);
		plaintext = cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext));
		
		return new String(plaintext);
	}
	
	/**
	 * Encrypt using AES algorithm
	 * @param plaintext - text to encrypt
	 * @param key - AES key
	 * @return ciphertext
	 */
	protected String encryptWithAES(String plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] ciphertext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_ENCRYPTION);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		ciphertext = cipher.doFinal(plaintext.getBytes());
		
		return DatatypeConverter.printBase64Binary(ciphertext);
	}
	
	
	/**
	 * Decrypt using AES algorithm
	 * @param ciphertext - text to decrypt
	 * @param key - AES key
	 * @return plaintext
	 */
	protected String decryptWithAES(String ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		byte[] plaintext = null;
		Cipher cipher = Cipher.getInstance(ALGORITHM_ENCRYPTION);
		cipher.init(Cipher.DECRYPT_MODE, key);
		plaintext = cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext));
		
		return new String(plaintext);
	}
	
	/**
	 * Key is encrypted using receiver's public key, so use private key to decrypt
	 * Used to verify receiver's identity
	 * @param encryptedKey - encrypted encryption key
	 * @param pvKey - private key of receiver
	 * @return encryption key in bytes
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
	 * Then decrypts the message with the sender public key
	 * Used to verify sender's identity
	 * @param response - text to decrypt
	 * @param enKeyBytes - encryption key in bytes
	 * @param pbKey - public key of sender
	 * @return authentication message that includes timestamp and g^n mod p
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
		waitForCont();
		
		return message;
	}
	
	/**
	 * Extracts the shared DH and calculates a secret DH to use as a session key for encrypting and decrypting data transferred
	 * Session key is used to encrypt messages sent and will be forgotten later
	 * @param sharedDH - g^n mod p
	 * @param secretValue - secret value of the server/client to use for DH exchange
	 * @return g^(ab) mod p
	 */
	protected SecretKey calculateMessageEncryptionKey(String sharedDH) {
		SecretKey messageKey;
		try {
			BigInteger secretDH = calculateSecretDH(new BigInteger(sharedDH));
			
			log("Secret DH: " + secretDH.toString());
			waitForCont();
			
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
	 * Encrypt the authentication encryption key with the receiver's public key
	 * Used to authenticate the receiver because it could only be decrypted with their private key
	 * @param enKey - encryption key to encrypt
	 * @param pbKey - public key of receiver
	 * @return encrypted encryption key
	 */
	protected String encryptAuthenticationEncryptionKey(SecretKey enKey, PublicKey pbKey) {
		String encryptedKey;
		try {
			log('\n' + "Encrypting AES key..." + '\n');
			
			String encryptionKey = DatatypeConverter.printBase64Binary(enKey.getEncoded());
			
			log("Authentication Encryption key: " + encryptionKey);
			waitForCont();
			
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
	 * Signs the timestamp and shared DH with sender's private key
	 * used to verify the sender's identity
	 * @param secretValue - g^(ab) mod p
	 * @param pvKey - private key of sender
	 * @return
	 */
	protected String signAuthenticationMessage(PrivateKey pvKey) {		
		String signedMsg;
		try {
			long timestamp = System.currentTimeMillis();
			BigInteger sharedDH = calculateSharedDH();
				
			log('\n' + "Signing timestamp (" + timestamp + ") and shared DH (" + sharedDH.toString() + ") for authentication..." + '\n');
			
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
	 * Encrypts the authentication message with the key encrypted by the receiver's public key
	 * Used verifies receiver's indentity
	 * @param message - message to encrypt
	 * @param enKey - encryption key
	 * @return encrypted message
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
	
	/**
	 * Generates a secret value to use in DH exchange
	 */
	protected void generateSecretValue() {
		Random rand = new Random(System.currentTimeMillis());
		n = BigInteger.valueOf(rand.nextInt(MIN_SECRET_VALUE) + MIN_SECRET_VALUE);
	}
	
	/**
	 * Generates MAC from message
	 */
	protected String generateMAC(String message, String keyString) throws InvalidKeyException, NoSuchAlgorithmException {
		Mac mac = Mac.getInstance(ALGORITHM_MAC);
		mac.init(generateSecretKey(keyString.getBytes(), ALGORITHM_MAC));
		byte[] digest = mac.doFinal(message.getBytes());
		return DatatypeConverter.printBase64Binary(digest);
	}
	
	/**
	 * Generates key for encrypting messages using g^(ab) mod p
	 */
	protected SecretKey generateMessageKey(BigInteger secretDH) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(ALGORITHM_HASH);
		byte[] msgKeyBytes = md.digest(secretDH.toByteArray());
		return generateSecretKey(msgKeyBytes);
	}
	
	/**
	 * Generates private key from string
	 */
	protected PrivateKey generatePrivateKey(String protectedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM_SIGNING);
		
		byte[] encodedPv = DatatypeConverter.parseBase64Binary(protectedKey);
		PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(encodedPv);
		return kf.generatePrivate(keySpecPv);
	}
	
	/**
	 * Generates public key from string
	 */
	protected PublicKey generatePublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM_SIGNING);
		
		byte[] encodedPb = DatatypeConverter.parseBase64Binary(publicKey);
		X509EncodedKeySpec keySpecPb = new X509EncodedKeySpec(encodedPb);
		return kf.generatePublic(keySpecPb);	
	}
	
	/**
	 * Generates a random secret key for AES encryption
	 */
	protected SecretKey generateSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_ENCRYPTION);
		keyGen.init(128);
		return keyGen.generateKey();
	}
	
	/**
	 * Generates a secret key for AES encryption with given key bytes
	 */
	protected SecretKey generateSecretKey(byte[] keyBytes) {
		return generateSecretKey(keyBytes, ALGORITHM_ENCRYPTION);
	}
	
	/**
	 * Generates a secret key for given encryption algorithm with given key bytes
	 */
	protected SecretKey generateSecretKey(byte[] keyBytes, String algorithm) {
		return new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
	}
	
	/**
	 * Convenient method for logging authentication process
	 */
	protected void log(String msg) {
		VirtualPrivateNetwork.log(msg);
	}

	protected void setMessageKey(SecretKey msgKey) {
		this.msgKey = msgKey;
	}
	
	protected void setIn(BufferedReader in) {
		this.in = in;
	}
	
	protected void setOut(DataOutputStream out) {
		this.out = out;
	}
	
	/**
	 * Receives and display messages from the client
	 */
	protected void communicate() {
		Runnable readTask = new Runnable() {

			@Override
			public void run() {
				try {
					String input;
					while ((input = in.readLine()) != null) {
						readEncryptedMessage(input);
						
					}
				} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
						| BadPaddingException | IOException e) {
					log("Cannot read or decrypt messages from client. Communication aborted.");
					VirtualPrivateNetwork.connect(false);
				}
			}
			
		};
		
		Thread readThread = new Thread(readTask);
		readThread.start();
	}
	
	/**
	 * Decrypts the message and prints it on the display
	 */
	protected void readEncryptedMessage(String input) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		log("Incoming message: " + input);
		
		//part[0] has message, part[1] has MAC
		String[] parts = input.split(DIVIDER);
		
		parts[0] = decryptWithAES(parts[0], msgKey);
		
		if (checkMAC(parts[0], parts[1])) {
			
			VirtualPrivateNetwork.display(parts[0]);
		} else {
			log('\n' + "MAC incorrect.");
		}
	}
	
	/**
	 * Validates the mac
	 */
	protected boolean checkMAC(String message, String mac) throws InvalidKeyException, NoSuchAlgorithmException {
		String macCheck = generateMAC(message, VirtualPrivateNetwork.getMACKey());
		log('\n' + "MAC: " + macCheck);
		return macCheck.equals(mac);	
	}
	
	/**
	 * Writes to the server
	 */
	public void write(String output) {
		try {
			String mac = generateMAC(output, VirtualPrivateNetwork.getMACKey());
			log("MAC: " + mac);
			
			output = encryptWithAES(output, msgKey);
			output += DIVIDER + mac;
			
			VirtualPrivateNetwork.log('\n' + "Outgoing message:" + output);
			out.writeBytes(output + '\n');
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			log("Cannot write or encrypt messages to server.");
			log(e.getMessage());
			return;
		}
		
	}
	
	/**
	 * Waits for continue button to be clicked before moving to the next step in authentication
	 */
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
