package virtual_private_network;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

public class Server extends Crypto {
	private static final int BACKLOG = 10;

	//private and public keys established beforehand
	private static final String SERVER_PRIVATE_KEY = "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";
	private static final String CLIENT_PUBLIC_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtmj/2AIWehtE9OaGL6QD+yWFbiutspvRR1imWcQ67z6sGluPiHejmcIPX5HMl/4c7ctOta3WNCgEv0Dp/dTRdGVYvpnf3CYKZ8bxTxuliVx9HRw0hGQA3YaKWWpGIUMYa0EaEUn0dgHbse4WPv0SySCSwNVNhCiLpq6ZoMd0Lx5ru6lHmwNFRCahftR6/n4jCSlwTbvgbYtt84dwMfL3XoaObwCry2b80WQ302M4Ry3Jc11lLEyBT6i+N9eB7WN1tHM6MULs9mRKrftjG3G6uPOLYclljv8NovBByS2WQC7hv6cHHzphTBCUuwJSDuVYSwUW0XEbH/ODJeopnlDG/1QVkG2m2JgF6+xSepW7/5WP7i1kR3e+VQi2e0pIO/7zOHOlI58or98Jfv3FukB6M8Nkz9wtognCFC8Va3Z4NlGUccyKaTNBIRnfYTzRyLCokmZBnz1VZKdYFVymsDQQXF0eJP0BczIWBIYhRaVOSM5lFlJ7y0e6lG4l8hgvfvXsqcWX9NnvMP4rn66eqwYnHyvJIf0HaYXhZlHBTK5FgqZ5u8GrV0u9w31H00u9RC6LtI99ih0w6SizpwnF+qQqdpBO39OuGSmrlvHCkog3lPsel/2hUm6Mk0X9JwWUi5jRr0OjslJHZW+74pA0/jMSszazp6mR4KHfZ0tequgDlusCAwEAAQ==";
	
	private ServerSocket server;
	
	public Server(String host, int port) throws IOException {
		log('\n' + "Creating a server with IP " + host + " at port " + port + "..." + '\n');
		
		InetAddress ip = InetAddress.getByName(host);
		
		server = new ServerSocket(port, BACKLOG, ip);
		log("Successful created a server with IP " + host + " at port " + port);
	}
	
	public void start() throws IOException {
		log('\n' + "Waiting for client..." + '\n');
		
		Socket connection = server.accept();
		log("Connection with client established"); 
		
		setIn(new BufferedReader(new InputStreamReader(connection.getInputStream())));
		setOut(new DataOutputStream(connection.getOutputStream()));
		
		authenticate();
	}
	
	private void authenticate() {
		//generates secret value for DH exchange
		generateSecretValue();
		
		//creates private key from previously established server's private key string
		PrivateKey pvKey;
		try {
			pvKey = generatePrivateKey(SERVER_PRIVATE_KEY);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			log("Cannot create public key. Authentication aborted.");
			return;
		}
		
		//creates public key from previously attained client's public key string
		PublicKey pbKey;
		try {
			pbKey = generatePublicKey(CLIENT_PUBLIC_KEY);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			log("Cannot create public key. Authentication aborted.");
			return;
		}
		
		log('\n' + "Authenticating client..." + '\n');
		
		String response;
		try {
			response = in.readLine();
		} catch (IOException e) {
			log("Cannot read from client. Authentication aborted");
			return;
		}
		
		//parts[0] is encrypted key, parts[1] is encrypted messaged
		String[] parts = response.split(DIVIDER);
		
		log("Received authentication message: " + response);
		log('\n' + "Decrypting authentication message..." + '\n');
		
		//extracts the encryption key used to encrypt the message, uses server's private key
		byte[] enKeyBytes = extractAuthenticationEncryptionKey(parts[0], pvKey);			
		if (enKeyBytes == null) {
			log("Authentication failed");
			return;
		}
		
		//decrypts the message with the encryption key found before and then the client's public key
		response = decryptAuthenticationMessage(parts[1], enKeyBytes, pbKey);
		if (response == null) {
			log("Authentication failed");
			return;
		}
		
		//parts[0] is the timestamp, parts[1] is the shared DH Value
		parts = response.split(DIVIDER);
		
		//calculates the encryption key using g^b mod p, sent in the message and the server's secret value a
		setMessageKey(calculateMessageEncryptionKey(parts[1]));
		if (msgKey == null) {
			log("Authentication failed");
			return;
		}
		
		//prevents replay attack by checking timestamp
		long timestamp = Long.parseLong(parts[0]);
		log("Timestamp: " + timestamp);
		log("Current timestamp: " + System.currentTimeMillis() + '\n');
		if (System.currentTimeMillis() - timestamp > 60000) {
			log("Timestamp is invalid");
			return;
		} else {
			log("Timestamp valid");
			waitForCont();
		}
		
		//generates a random key to use to encrypt the authentication message
		SecretKey enKey;
		try {
			enKey = generateSecretKey();
		} catch (NoSuchAlgorithmException e) {
			log("Cannot create encryption key. Authentication aborted.");
			return;
		}
		
		//encrypts the encryption key with the client's public key
		String encryptedKey = encryptAuthenticationEncryptionKey(enKey, pbKey);
		if (encryptedKey == null) {
			log("Authentication failed");
			return;
		}
		
		//sign the message that includes timestamp and shared DH with the server's private key
		String signedMsg = signAuthenticationMessage(pvKey);
		if (signedMsg == null) {
			log("Authentication failed");
			return;
		}
		
		//encrypts the message with the encryption key generated before
		String encryptedMsg = encryptAuthenticationMessage(signedMsg, enKey);
		if (encryptedMsg == null) {
			log("Authentication failed");
			return;
		}
		
		try {
			//send both the encrypted encryption key and the encrypted message
			String msg = encryptedKey + DIVIDER + encryptedMsg;
			out.writeBytes(msg + '\n');
			
			log("Message sent: " + msg);
		} catch (IOException e) {
			log("Cannot write to client. Authentication aborted");
			return;
		}
		
		log('\n' + "Communication established" + '\n');
		VirtualPrivateNetwork.connect(true);
		
		communicate();
	}
}
