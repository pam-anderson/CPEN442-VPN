package virtual_private_network;

import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class VirtualPrivateNetwork {	
	//default size of text boxes
	private static final int TEXT_FIELD_HEIGHT = 10;
	private static final int TEXT_FIELD_WIDTH = 50;
	
	// used for DH exchange, established beforehand
	private static final String P = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D70C354E4ABC9804F1746C08CA18217C32905E462E36CE3B39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9E2BCBF6955817183995497CEA956AE515D2261898FA05105728E5A8AACAA68FFFFFFFFFFFFFFFF";
	private static final String G = "2";
	
	// default shared secret value
	private static final String MAC_KEY = "CPEN442";
	
	// host and port used for setting up TCP connection
	private static final String DEFAULT_HOST = "127.0.0.1";
	private static final String DEFAULT_PORT = "5007";
	
	//window name
	private static final String FRAME_NAME = "Virtual Private Network";
	
	//button names
	private static final String SERVER = "Server";
	private static final String CLIENT = "Client";
	private static final String START = "Start Connection";
	private static final String CONTINUE = "Continue";
	
	//field names
	private static final String HOST = "IP Address: ";
	private static final String PORT = "Port: ";
	private static final String SHARED_VALUE = "Shared Secret Value";
	private static final String RECEIVE = "Data as Received";
	private static final String SEND = "Data to be Send";
	private static final String SEND_BUTTON = "Send";
	private static final String PROCESS = "Process";
	
	private static Crypto program;
	
	private static JFrame frame;
	
	private static JButton serverButton;
	private static JButton clientButton;
	private static JButton startButton;
	private static JButton sendButton;
	private static JButton continueButton;
	
	private static JTextField host;
	private static JTextField port;
	private static JTextField sharedValue;
	
	private static JTextArea output;
	private static JTextArea input;
	private static JTextArea process;
	
	// whether or not client/server is connected to each other
	private static boolean connected;
	
	// whether or not to continue to the next stage of authentication
	private static boolean cont;
	
	// client or server mode
	private static boolean mode;
	
	//public and shared between server and client, used for DH exchange
	private static BigInteger p;
	private static BigInteger g;
	
	// shared secret value used for hashing messages for the MAC
	private static String macKey;
	
	public static void main(String argv[]) {
		init();
	}
	
	/**
	 * Sets connected, used only when communication has been established or disconnected
	 */
	public static void connect(boolean con) {
		connected = con;
		
		if (connected) {
			continueButton.setEnabled(false);
			sendButton.setEnabled(true);
			output.setEditable(true);
		} else {
			continueButton.setEnabled(true);
			sendButton.setEnabled(false);
			output.setEditable(false);
		}
		
		frame.pack();
	}
	
	public static void setContinue(boolean cont) {
		VirtualPrivateNetwork.cont = cont;
	}
	
	public static boolean getContinue() {
		return cont;
	}
	
	public static String getMACKey() {
		return macKey;
	}
	
	public static BigInteger getP() {
		return p;
	}
	
	public static BigInteger getG() {
		return g;
	}
	
	/**
	 * displays data received from client
	 * @param in - data received
	 */
	public static void display(String in) {
		input.insert(in + '\n', 0);
	}
	
	/**
	 * logs the steps in authenticating and transferring data
	 * @param message - log message
	 */
	public static void log(String message) {
		process.insert(message + '\n', 0);
		process.setCaretPosition(0);
	}
	
	/**
	 * initialize the GUI
	 */
	private static void init() {
		p = new BigInteger(P, 16);
		g = new BigInteger(G);
		macKey = MAC_KEY;
		connected = false;
		cont = false;
		
		frame = new JFrame(FRAME_NAME);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		
		serverButton = new JButton(SERVER);
		serverButton.setSize(100, 50);
		serverButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				setServerMode();
			}
			
		});		
		
		clientButton = new JButton(CLIENT);
		clientButton.setSize(100, 50);
		clientButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setClientMode();
			}
			
		});
		
		startButton = new JButton(START);
		startButton.setSize(100, 50);
		startButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent arg0) {
				disableActions();
				
				macKey = sharedValue.getText();
				
				startConnection();
			}
			
		});
		
		JPanel buttons = new JPanel(new FlowLayout());
		buttons.add(serverButton);
		buttons.add(clientButton);
		buttons.add(startButton);
		frame.getContentPane().add(buttons, gbc);
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(HOST), gbc);
		
		host = new JTextField(DEFAULT_HOST, TEXT_FIELD_WIDTH);
		host.setHorizontalAlignment(SwingConstants.CENTER);
		gbc.gridy++;
		frame.getContentPane().add(host, gbc);		
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(PORT), gbc);
		
		port = new JTextField(DEFAULT_PORT, TEXT_FIELD_WIDTH);
		port.setHorizontalAlignment(SwingConstants.CENTER);
		gbc.gridy++;
		frame.getContentPane().add(port, gbc);
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(SHARED_VALUE), gbc);
		
		sharedValue = new JTextField(macKey.toString(), TEXT_FIELD_WIDTH);
		sharedValue.setHorizontalAlignment(SwingConstants.CENTER);
		gbc.gridy++;
		frame.getContentPane().add(sharedValue, gbc);		
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(SEND), gbc);
		
		output = new JTextArea(TEXT_FIELD_HEIGHT, TEXT_FIELD_WIDTH);
		output.setEditable(false);
		gbc.gridy++;
		frame.getContentPane().add(new JScrollPane(output), gbc);
		
		sendButton = new JButton(SEND_BUTTON);
		sendButton.setSize(100, 50);
		sendButton.addActionListener(new ActionListener() {

			//sends message with the enter button
			@Override
			public void actionPerformed(ActionEvent e) {
				if (connected) {
					write();					
					output.setText("");
				}
			}
			
		});
		gbc.gridy++;
		frame.getContentPane().add(sendButton, gbc);
		sendButton.setEnabled(false);
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(RECEIVE), gbc);
		
		input = new JTextArea(TEXT_FIELD_HEIGHT, TEXT_FIELD_WIDTH);
		input.setEditable(false);
		gbc.gridy++;
		frame.getContentPane().add(new JScrollPane(input), gbc);
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(PROCESS), gbc);
		
		process = new JTextArea(TEXT_FIELD_HEIGHT, TEXT_FIELD_WIDTH);
		process.setEditable(false);
		gbc.gridy++;
		frame.getContentPane().add(new JScrollPane(process), gbc);
		
		continueButton = new JButton(CONTINUE);
		continueButton.setSize(100, 50);
		continueButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setContinue(true);
			}
		});
		gbc.gridy++;
		frame.getContentPane().add(continueButton, gbc);
		continueButton.setEnabled(false);
		
		setServerMode();
		
		frame.pack();
		frame.setVisible(true);
	}
	
	/**
	 * Puts the program in client mode
	 */
	private static void setClientMode() {
		mode = false;
		
		serverButton.setEnabled(true);
		clientButton.setEnabled(false);
	}
	
	/**
	 * Puts the program in server mode
	 */
	private static void setServerMode() {
		mode = true;
		
		serverButton.setEnabled(false);
		clientButton.setEnabled(true);
	}
	
	/**
	 * Creates and starts the server or client depending on mode
	 */
	private static void startConnection() {
		if (mode) {
			Runnable serverTask = new Runnable() {
				
				//starts server on new thread
				@Override
				public void run() {
					try {
						program = new Server(host.getText(), Integer.parseInt(port.getText()));
						((Server) program).start();
					} catch (Exception e) {
						log("Error with server");
						log(e.getMessage());
						
						enableActions();
					}
				}
				
			};
			
			Thread serverThread = new Thread(serverTask);
			serverThread.start();
		} else {
			Runnable clientTask = new Runnable() {
				
				//starts client on new thread
				@Override
				public void run() {
					try {
						program = new Client(host.getText(), Integer.parseInt(port.getText()));
					} catch (Exception e) {
						log("Error with client");
						log(e.getMessage());
						
						enableActions();
					}
				}
				
			};
			
			Thread clientThread = new Thread(clientTask);
			clientThread.start();
		}
	}
	
	/**
	 * Used by the client to record enter events and write to server
	 */
	private static void write() {
		try {
			program.write(output.getText());
		} catch (Exception e) {
			log("Error writing to server");
			log(e.getMessage());
			e.printStackTrace();
		}
	}
	
	/**
	 * Disable configuration buttons and text fields when connection established
	 */
	private static void disableActions() {
		serverButton.setEnabled(false);
		clientButton.setEnabled(false);
		startButton.setEnabled(false);
		continueButton.setEnabled(true);
		
		host.setEnabled(false);
		host.setBackground(Color.LIGHT_GRAY);
		
		port.setEnabled(false);
		port.setBackground(Color.LIGHT_GRAY);
		
		sharedValue.setEnabled(false);
		sharedValue.setBackground(Color.LIGHT_GRAY);
	}
	
	/**
	 * Enable buttons and text fields for configuration
	 */
	private static void enableActions() {
		serverButton.setEnabled(true);
		clientButton.setEnabled(true);
		startButton.setEnabled(true);
		sendButton.setEnabled(false);;
		
		output.setEditable(false);
		
		host.setEnabled(true);
		host.setBackground(Color.WHITE);
		
		port.setEnabled(true);
		port.setBackground(Color.WHITE);
		
		sharedValue.setEnabled(true);
		sharedValue.setBackground(Color.WHITE);
	}
}
