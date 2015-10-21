package virtual_private_network;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Client extends Crypto {

	private static final String CLIENT_PRIVATE_KEY = "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";
	private static final String SERVER_PUBLIC_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwmCK+M6mxkMZRUhHWRgrfvqKPZyAaKTH1wyNL69BvZ0RMwpY+u4XttOsTpVKZ0/GS3rM8NHAs07EUkUQn0tm8MlTmPsLbU89KH01IU559c4MDKT6Q0p05KhIVM8hRGtfY9dHiEGxdOwGFiTxqg74eWpR+/dbkW10nXaBXPilptA53XMf8A3s5nsRkxKK+wb9t740u6BepgWTmYQp/zSssYBruqJY03nO7AH7btic8ZZUY0NNQGUjFB1G/EYnxpDFdUGz8wPB5jJ4fiBvW/uqY5sOjHRwcfFVu3J+vRjknaI/ESC/N+DZ8yJyUJYpr8kumX9Zes+T4wCiQAwGgtSzsgee2HZkJ6WXBCXpCkHRJtxUWbe8Fkh/DvudHIinL+x29cB9+tR1poy3Cod+TpQuxkMG4T3W2vGOSE9r7bijfvvQCfN6bK0SY6Ybic6VlzTw1KV+1A7LdolZiF3SBye5c3HWv+h82BFDCVldj8YEw1qp8W+bb75Upy6iya6O+IO3RxO73RZymqygYGnpNzzFU2eILpx9P1nCkTrPTh3ee5Ki5IgWwrIAcMwfkPnHNIo05mBDj/EQ1MI4pPYCapmGTs0M5L562PbtaKaW4IylnL+lsG1Lwz9DFr7PILINzm1TE3RCf8NWuVMSD0wvCFxF+ZYRau6ztlFUog/9py8x6xkCAwEAAQ==";
	
	private Socket client;
	
	private BigInteger b;
	private SecretKey msgKey;
	
	private BufferedReader in;
	private DataOutputStream out;
	
	public Client(String host, int port) throws UnknownHostException, IOException {
		VirtualPrivateNetwork.log('\n' + "Connecting to server..." + '\n');
		client = new Socket(host, port);
		VirtualPrivateNetwork.log("Connection with server has been established");
		
		in = new BufferedReader(new InputStreamReader(client.getInputStream()));
		out = new DataOutputStream(client.getOutputStream());
		
		authenticate();
		
	}
	
	public void write(String output) {
		try {
			output = encryptWithAES(output, msgKey);
			VirtualPrivateNetwork.log("Outgoing message:" + output);
			out.writeBytes(output + '\n');
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			log("Cannot write or encrypt messages to server.");
			return;
		}
		
	}
	
	private void authenticate() {
		Random rand = new Random(System.currentTimeMillis());
		b = BigInteger.valueOf(rand.nextInt(MIN_SECRET_VALUE) + MIN_SECRET_VALUE);
		
		PrivateKey pvKey;
		try {
			pvKey = generatePrivateKey(CLIENT_PRIVATE_KEY);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			log("Cannot create public key. Authentication aborted.");
			return;
		}
		
		PublicKey pbKey;
		try {
			pbKey = generatePublicKey(SERVER_PUBLIC_KEY);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			log("Cannot create public key. Authentication aborted.");
			return;
		}
		
		VirtualPrivateNetwork.log('\n' + "Authenticating with server...");
		
		//generates a random key to use to encrypt the authentication message
		SecretKey enKey;
		try {
			enKey = generateSecretKey();
		} catch (NoSuchAlgorithmException e) {
			log("Cannot create encryption key. Authentication aborted.");
			return;
		}
		String encryptedKey = encryptAuthenticationEncryptionKey(enKey, pbKey);
		if (encryptedKey == null) {
			log("Authentication failed");
			return;
		}
		
		//sign the message that includes timestamp and shared DH
		String signedMsg = signAuthenticationMessage(b, pvKey);
		if (signedMsg == null) {
			log("Authentication failed");
			return;
		}
		
		String encryptedMsg = encryptAuthenticationMessage(signedMsg, enKey);
		if (encryptedMsg == null) {
			log("Authentication failed");
			return;
		}
		
		try {
			out.writeBytes(encryptedKey + ";" + encryptedMsg + '\n');
		} catch (IOException e) {
			log("Cannot write to client. Authentication aborted");
			return;
		}
		
		log('\n' + "Waiting for server's response..." + '\n');
		String response;
		try {
			response = in.readLine();
		} catch (IOException e) {
			log("Cannot read from client. Authentication aborted");
			return;
		}
		
		//parts[0] is encrypted key, parts[1] is encrypted messaged
		String[] parts = response.split(";");
		
		log("Received authentication message: " + response);
		log('\n' + "Decrypting authentication message..." + '\n');
		
		byte[] enKeyBytes = extractAuthenticationEncryptionKey(parts[0], pvKey);			
		if (enKeyBytes == null) {
			log("Authentication failed");
			return;
		}
		
		response = decryptAuthenticationMessage(parts[1], enKeyBytes, pbKey);
		if (response == null) {
			log("Authentication failed");
			return;
		}
		
		//parts[0] is the timestamp, parts[1] is the shared DH Value
		parts = response.split(";");
		
		msgKey = extractMessageEncryptionKey(parts[1], b);
		if (msgKey == null) {
			log("Authentication failed");
			return;
		}
		
		//prevents replay attack by checking timestamp
		long timestamp = Long.parseLong(parts[0]);
		if (timestamp - System.currentTimeMillis() > 2000) {
			log("Timestamp is invalid");
			return;
		}		
		
		VirtualPrivateNetwork.log("Communication confirmed.");
		VirtualPrivateNetwork.connect(true);
	}
}
