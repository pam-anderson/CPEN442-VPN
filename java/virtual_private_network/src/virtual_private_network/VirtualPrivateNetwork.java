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
	
	// used for DH exchange, can be changed
	private static final String DEFAULT_P = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D70C354E4ABC9804F1746C08CA18217C32905E462E36CE3B39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9E2BCBF6955817183995497CEA956AE515D2261898FA05105728E5A8AACAA68FFFFFFFFFFFFFFFF";
	private static final String DEFAULT_G = "2";
	
	// host and port used for setting up TCP connection
	private static final String DEFAULT_HOST = "127.0.0.1";
	private static final String DEFAULT_PORT = "5007";
	
	private static final String FRAME_NAME = "Virtual Private Network";
	private static final String SERVER = "Server";
	private static final String CLIENT = "Client";
	private static final String START = "Start Connection";
	private static final String CONTINUE = "Continue";
	
	private static final String HOST = "IP Address: ";
	private static final String PORT = "Port: ";
	private static final String P = "p";
	private static final String G = "g";
	private static final String RECEIVE = "Data as Received";
	private static final String SEND = "Data to be Send";
	private static final String PROCESS = "Process";
	
	private static Client client;
	
	private static JFrame frame;
	private static JTextArea process;
	private static JTextArea input;
	private static JTextField host;
	private static JTextField port;
	private static JTextField output;
	private static JTextField pField;
	private static JTextField gField;
	
	private static boolean connected;
	private static boolean cont;
	private static boolean mode;
	
	//public and shared between server and client
	private static BigInteger p;
	private static BigInteger g;
	
	public static void main(String argv[]) {
		init();
	}
	
	public static void connect(boolean connected) {
		VirtualPrivateNetwork.connected = connected;
	}
	
	public static void setContinue(boolean cont) {
		VirtualPrivateNetwork.cont = cont;
	}
	
	public static boolean getContinue() {
		return cont;
	}
	
	/**
	 * displays data received from client
	 * @param in - data received
	 */
	public static void display(String in) {
		input.setText(in + '\n' + input.getText());
	}
	
	public static BigInteger getP() {
		return p;
	}
	
	public static BigInteger getG() {
		return g;
	}
	
	/**
	 * logs the steps in authenticating and transferring data
	 * @param message - log message
	 */
	public static void log(String message) {
		process.setText(message + '\n' + process.getText());
	}
	
	/**
	 * initialize the GUI
	 */
	private static void init() {
		p = new BigInteger(DEFAULT_P, 16);
		g = new BigInteger(DEFAULT_G);
		connected = false;
		
		frame = new JFrame(FRAME_NAME);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		
		final JButton serverButton = new JButton(SERVER);
		serverButton.setSize(100, 50);
		serverButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				setServerMode();
			}
			
		});		
		
		final JButton clientButton = new JButton(CLIENT);
		clientButton.setSize(100, 50);
		clientButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setClientMode();
			}
		});
		
		final JButton startButton = new JButton(START);
		startButton.setSize(100, 50);
		startButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent arg0) {
				serverButton.setEnabled(false);
				clientButton.setEnabled(false);
				startButton.setEnabled(false);
				
				host.setEnabled(false);
				host.setBackground(Color.LIGHT_GRAY);
				
				port.setEnabled(false);
				port.setBackground(Color.LIGHT_GRAY);
				
				p = new BigInteger(pField.getText());
				pField.setEnabled(false);
				pField.setBackground(Color.LIGHT_GRAY);
				
				g = new BigInteger(gField.getText());
				gField.setEnabled(false);
				gField.setBackground(Color.LIGHT_GRAY);
				
				cont = false;
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
		frame.getContentPane().add(new JLabel(P), gbc);
		
		pField = new JTextField(p.toString(), TEXT_FIELD_WIDTH);
		pField.setHorizontalAlignment(SwingConstants.CENTER);
		gbc.gridy++;
		frame.getContentPane().add(pField, gbc);		
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(G), gbc);
		
		gField = new JTextField(g.toString(), TEXT_FIELD_WIDTH);
		gField.setHorizontalAlignment(SwingConstants.CENTER);
		gbc.gridy++;
		frame.getContentPane().add(gField, gbc);
		
		gbc.gridy++;
		frame.getContentPane().add(new JLabel(SEND), gbc);
		
		output = new JTextField(TEXT_FIELD_WIDTH);
		output.addActionListener(new ActionListener() {
			
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
		frame.getContentPane().add(output, gbc);
		
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
		
		final JButton continueButton = new JButton(CONTINUE);
		continueButton.setSize(100, 50);
		continueButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setContinue(true);
			}
		});
		gbc.gridy++;
		frame.getContentPane().add(continueButton, gbc);
		
		setServerMode();
		
		frame.pack();
		frame.setVisible(true);
	}
	
	private static void setClientMode() {
		mode = false;
		
		input.setEnabled(false);
		input.setBackground(Color.LIGHT_GRAY);
		
		output.setEnabled(true);
		output.setBackground(Color.WHITE);
	}
	
	private static void setServerMode() {
		mode = true;
		
		input.setEnabled(true);
		input.setBackground(Color.WHITE);
		
		output.setEnabled(false);
		output.setBackground(Color.LIGHT_GRAY);
	}
	
	private static void startConnection() {
		if (mode) {
			Runnable serverTask = new Runnable() {
				
				//starts server on new thread
				@Override
				public void run() {
					try {
						Server server = new Server(host.getText(), Integer.parseInt(port.getText()));
						server.start();
					} catch (Exception e) {
						log("Error with server");
						log(e.getMessage());
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
						client = new Client(host.getText(), Integer.parseInt(port.getText()));
					} catch (Exception e) {
						log("Error with client");
						log(e.getMessage());
					}
				}
				
			};
			
			Thread clientThread = new Thread(clientTask);
			clientThread.start();
		}
	}
	
	/**
	 * used by the client to record enter events and write to server
	 */
	private static void write() {
		try {
			client.write(output.getText());
		} catch (Exception e) {
			log("Error writing to server");
			log(e.getMessage());
			e.printStackTrace();
		}
	}
}
