// A client-side class that uses a secure TCP/IP socket

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.ssl.*;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class VoterClient extends JFrame implements ActionListener{
	private InetAddress host;
	private int port;
	// This is not a reserved port number 
	static final int DEFAULT_CLA_PORT = 8188;
	static final int DEFAULT_CTF_PORT = 8189;
	static final String KEYSTORE = "PIERkeystore.ks";
	static final String TRUSTSTORE = "PIERtruststore.ks";
	static final String keySTOREPASSWD = "111111";
	static final String trustSTOREPASSWD = "7777777";
	static final String ALIASPASSWD = keySTOREPASSWD;
	
	/* JFrame components */ 
	static private JFrame mainFrame;					
	static private JButton btnCLA;						// to activate the CLA screen
	static private JButton btnCTF;						// to activate the CTF screen
	static private JButton btnQuit;						// to quit the main screen
	static private JButton btnReturn1;					// to return to the main screen
	static private JButton btnReturn2;					// to return to the main screen
	static private JTextField txtFieldCLA;				// to write the social security number in
	static private JTextField txtFieldCTF;				// to write the code in
	static private JTextArea txtFieldDisplayCode; 		// displays the code
	/* */
	/**
	 * 
	 * @param host
	 * @param port
	 */
	static VoterClient voterClient;

	private String textFieldValue = "";
	
/** =============================== CONSTRUCTORS ============================================**/
	/**
	 * Default constructor, used to initiate the JFrame
	 */
	public VoterClient(){
		// Initialize mainFrame, consisting of two buttons, btnCLA and btnCTF
		initJFrame();
		
	}

	// Constructor @param host Internet address of the host where the server is located
	// @param port Port number on the host where the server is listening
	public VoterClient( InetAddress host, int port ) {
		this.host = host;
		this.port = port;
	}
/** ========================================================================================= **/

/** =========================== Initialize JFrame components ================================ **/
	private void initJFrame() {
		mainFrame = new JFrame("FrameDemo");
		btnCLA = new JButton("Få ditt röstkort - CLA");
		btnCTF = new JButton("Rösta - CTF");
		btnQuit = new JButton("Exit");
		txtFieldDisplayCode = new JTextArea(5,20);
		txtFieldDisplayCode.setEditable(false);
		
		//2. Optional: What happens when the frame closes?
		mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		//3. Create components and put them in the frame.
		mainFrame.setLayout(new FlowLayout());
		
		// Add components
		mainFrame.add(txtFieldDisplayCode);
		mainFrame.add(btnCLA);
		mainFrame.add(btnCTF);
		mainFrame.add(btnQuit);
		
		btnCLA.addActionListener(this);
		btnCTF.addActionListener(this);
		btnQuit.addActionListener(this);
		
		//4. Size the frame.
		mainFrame.pack();

		//5. Show it.
		mainFrame.setVisible(true);	
	}
/** ========================================================================================= **/
	
/** =========================================== RUN ========================================= **/
  // The method used to start a client object
	public void runCLA(String ssn) {
		String validationCode = ""; 
		
		try
		{
			KeyStore ks = KeyStore.getInstance( "JCEKS" );
			ks.load( new FileInputStream( KEYSTORE ), keySTOREPASSWD.toCharArray() );
			
			KeyStore ts = KeyStore.getInstance( "JCEKS" );
			ts.load( new FileInputStream( TRUSTSTORE ), trustSTOREPASSWD.toCharArray() );
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
			kmf.init( ks, ALIASPASSWD.toCharArray() );
			
			TrustManagerFactory tmf = TrustManagerFactory.getInstance( "SunX509" );
			tmf.init( ts );
			
			SSLContext sslContext = SSLContext.getInstance( "TLS" );
			sslContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null );
			SSLSocketFactory sslFact = sslContext.getSocketFactory();      	
			SSLSocket client =  (SSLSocket)sslFact.createSocket(host, port);
			client.setEnabledCipherSuites( client.getSupportedCipherSuites() );
			
			System.out.println("\n>>>> Voter client <-> CLA SSL/TLS handshake completed");
			
			BufferedReader socketIn;
			socketIn = new BufferedReader( new InputStreamReader( client.getInputStream() ) );
			PrintWriter socketOut = new PrintWriter( client.getOutputStream(), true );
			
			BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));

			socketOut.println("VoterClient");
			socketOut.println(ssn);
			System.out.println("Voter client sending SSN " + ssn + " to CLA server");
			
			validationCode = socketIn.readLine();
			System.out.println( "Voter client received validation number " + validationCode + " from the CLA server");
			if(!validationCode.equals("")){
				txtFieldDisplayCode.setText(validationCode);
			}
			
			// Stop loop on server
			socketOut.println ( "" );
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}
	
	public void runCTF(String valCode)
	{
		try
		{	
			KeyStore ks = KeyStore.getInstance( "JCEKS" );
			ks.load( new FileInputStream( KEYSTORE ), keySTOREPASSWD.toCharArray() );
			
			KeyStore ts = KeyStore.getInstance( "JCEKS" );
			ts.load( new FileInputStream( TRUSTSTORE ), trustSTOREPASSWD.toCharArray() );
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
			kmf.init( ks, ALIASPASSWD.toCharArray() );
			
			TrustManagerFactory tmf = TrustManagerFactory.getInstance( "SunX509" );
			tmf.init( ts );
			
			SSLContext sslContext = SSLContext.getInstance( "TLS" );
			sslContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null );
			SSLSocketFactory sslFact = sslContext.getSocketFactory();      	
			SSLSocket client =  (SSLSocket)sslFact.createSocket(host, port);
			client.setEnabledCipherSuites( client.getSupportedCipherSuites() );
			
			System.out.println("\n>>>> Voter client <-> CTF SSL/TLS handshake completed");
			
			BufferedReader socketIn;
			socketIn = new BufferedReader( new InputStreamReader( client.getInputStream() ) );
			PrintWriter socketOut = new PrintWriter( client.getOutputStream(), true );
			
			BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));

			System.out.println("Voter client sending validation code " + valCode + " to CTF server");
			socketOut.println(valCode);
				
			// Stop loop on server
			// socketOut.println ( "" );
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}
/** ======================================================================================== **/	
	
/** ======================================== MAIN ========================================== **/	
	// The test method for the class @param args Optional port number and host name
	public static void main( String[] args )
	{
		
		VoterClient noClient = new VoterClient();
	}
/** ========================================================================================= **/
	
	
/** ======================================= ActionPerformed ================================== **/
	@Override
	public void actionPerformed(ActionEvent e) {
		System.out.println("============ In ActionPerfromed ============");
		if ( e.getSource() == btnCLA ){
			System.out.println("========== CLA Button is pressed ========== "); 
			removeMainFrameButtons();		// Remove btnCLA and btnCTF from mainFrame
			addTextFieldToMainFrameCLA();		// Insert a textField in mainFrame
		} 
		else if(e.getSource() == btnCTF){
			System.out.println("========== CTF Button is pressed ========== ");
			removeMainFrameButtons();		// Remove btnCLA and btnCTF from mainFrame
			addTextFieldToMainFrameCTF();	
		}
		else if(e.getSource() == btnQuit) {
			System.out.println("========= Quit Button is pressed ==========");
			System.exit(0);
			
		}
		else if(e.getSource() == btnReturn1){
			System.out.println("========== Return Button CLA is pressed =======");
			textFieldValue = txtFieldCLA.getText().toString();
			System.out.println("Personnummer = " + textFieldValue);
			removeCLAFrame();
			addMainFrameComponents();
			
			// CLA host
			try {
				InetAddress CLAHost = InetAddress.getLocalHost();
				int CLAPort = DEFAULT_CLA_PORT;
				
				voterClient = new VoterClient( CLAHost, CLAPort );
				voterClient.runCLA(textFieldValue);
			}
			catch ( UnknownHostException uhx ) {
				System.out.println( uhx );
				uhx.printStackTrace();
			}
			
			//voterClient.run(textFieldValue);
		}
		else if(e.getSource() == btnReturn2) {
			System.out.println("========== Return Button CTF is pressed =======");
			String textFieldValue2 = txtFieldCTF.getText();
			System.out.println("Kod = " + textFieldValue2);
			removeCTFFrame();
			addMainFrameComponents();
			
			// CTF host
			try {
				InetAddress CTFHost = InetAddress.getLocalHost();
				int CTFPort = DEFAULT_CTF_PORT;
				voterClient = new VoterClient( CTFHost, CTFPort );
				voterClient.runCTF(textFieldValue2);
			}
			catch ( UnknownHostException uhx ) {
				System.out.println( uhx );
				uhx.printStackTrace();
			}
			
		} else {
			
		}
	}
/** ========================================================================================= **/	
	
/** ========================== Functions called by actionPerformed ========================== **/
	
	
	private void removeCLAFrame() {
		btnReturn1.setVisible(false);
		txtFieldCLA.setVisible(false);
	}
	
	private void removeCTFFrame() {
		btnReturn2.setVisible(false);
		txtFieldCTF.setVisible(false);
	}
	
	private void addMainFrameComponents(){
		btnCLA.setVisible(true);
		btnCTF.setVisible(true);
		btnQuit.setVisible(true);
		
		mainFrame.repaint();
		mainFrame.validate();
	}
	

	/**
	 *	Method to remove the btnCLA and btnCTF from the mainFrame,
	 *	called when new components are to be added.
	 */
	private void removeMainFrameButtons() {
		btnCLA.setVisible(false);
		btnCTF.setVisible(false);
		btnQuit.setVisible(false);
	}
	
	/**
	 * Called when btnCLA is removed, and a textfield is to be added.
	 */
	private void addTextFieldToMainFrameCLA() {
		// Add a textField, with a tooltip
		txtFieldCLA = new JTextField(20);
		txtFieldCLA.setToolTipText("Ange personnummer");
		
		// Creating a temporary return button
		btnReturn1 = new JButton("Ok");
		
		// Add action listener to the return button
		btnReturn1.addActionListener(this);
		
		// Add the new changes to the mainFrame
		mainFrame.add(txtFieldCLA);
		mainFrame.add(btnReturn1);
		mainFrame.repaint();
		mainFrame.validate();
	}
	
	/**
	 * Called when btnCTF is removed, and a textfield is to be added.
	 */
	private void addTextFieldToMainFrameCTF() {
		// Add a textField, with a tooltip
		txtFieldCTF = new JTextField(20);
		txtFieldCTF.setToolTipText("Ange kod");
		
		// Creating a temporary return button
		btnReturn2 = new JButton("Ok");
		
		// Add action listener to the return button
		btnReturn2.addActionListener(this);
		
		// Add the new changes to the mainFrame
		mainFrame.add(txtFieldCTF);
		mainFrame.add(btnReturn2);
		mainFrame.repaint();
		mainFrame.validate();
	}
	
/** ========================================================================================== **/	
}
