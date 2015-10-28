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

public class VoterClient extends JFrame implements ActionListener{
	private InetAddress host;
	private int port;
	// This is not a reserved port number 
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "PIERkeystore.ks";
	static final String TRUSTSTORE = "PIERtruststore.ks";
	static final String keySTOREPASSWD = "111111";
	static final String trustSTOREPASSWD = "7777777";
	static final String ALIASPASSWD = keySTOREPASSWD;
	
	// Constructor @param host Internet address of the host where the server is located
	// @param port Port number on the host where the server is listening
	public VoterClient( InetAddress host, int port ) {
		this.host = host;
		this.port = port;
	}
	
  // The method used to start a client object
	public void run() {
		try {
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
			
			System.out.println("\n>>>> SSL/TLS handshake completed");
			
			BufferedReader socketIn;
			socketIn = new BufferedReader( new InputStreamReader( client.getInputStream() ) );
			PrintWriter socketOut = new PrintWriter( client.getOutputStream(), true );
			
			BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));

			System.out.println("Klienten skickar sitt personnummer till CLA");
//			String file_download = "a.txt";
//			String file_upload = "new.txt";
//			String file_delete = "delete.txt";
//			String filecontents = "emma pemma heter jag o jag är så god o glad.";
//			
//			// Download
//			System.out.println("\n=== Downloading ===");
//			socketOut.println("download");
//			socketOut.println(file_download);
//			// Print response from server
//			System.out.println( socketIn.readLine() );
//				
//			// Upload
//			System.out.println("\n=== Uploading ===");
//			socketOut.println("upload");
//			socketOut.println(file_upload);
//			socketOut.println(filecontents.length());
//			socketOut.println(filecontents);
//			// Print response from server
//			System.out.println( socketIn.readLine() );
//			
//			// Delete
//			System.out.println("\n=== Deleting ===");
//			socketOut.println("delete");
//			socketOut.println(file_delete);
//			// Print response from server
//			System.out.println( socketIn.readLine() );
			
			/*
			String s;
			s = bufferRead.readLine();
			while(s != null && s.length() != 0)
			{
				System.out.println( ">>>> Sending " + s + " to SecureAdditionServer" );
				socketOut.println( s );
				s = bufferRead.readLine();
			}
			*/
		    
			// Stop loop on server
			socketOut.println ( "" );
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}
	
	
	// The test method for the class @param args Optional port number and host name
	public static void main( String[] args ) {
		initJFrame();
		
		try {
			InetAddress host = InetAddress.getLocalHost();
			int port = DEFAULT_PORT;
			if ( args.length > 0 ) {
				port = Integer.parseInt( args[0] );
			}
			if ( args.length > 1 ) {
				host = InetAddress.getByName( args[1] );
			}
			VoterClient addClient = new VoterClient( host, port );
			addClient.run();
		}
		catch ( UnknownHostException uhx ) {
			System.out.println( uhx );
			uhx.printStackTrace();
		}
	}

	private static void initJFrame() {
		//1. Create the frame.
		JFrame frame = new JFrame("FrameDemo");
		JButton btnCLA = new JButton("Få ditt röstkort - CLA");
		JButton btnCTF = new JButton("Rösta - CTF");
		
		//2. Optional: What happens when the frame closes?
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		//3. Create components and put them in the frame.
		//...create emptyLabel...
		//frame.getContentPane().add(emptyLabel, BorderLayout.CENTER);
		frame.setLayout(new FlowLayout());
		
		// Add components
		frame.add(btnCLA);
		frame.add(btnCTF);
		
		btnCLA.addActionListener(new ActionListener() { 
			public void actionPerformed(ActionEvent e) { 
				System.out.println("========== CLA Button is pressed ========== ");			  
			} 
		} );
		
		btnCTF.addActionListener(new ActionListener() { 
			public void actionPerformed(ActionEvent e) { 
				System.out.println("========== CTF Button is pressed ========== ");			  
			} 
		} );
		
		//4. Size the frame.
		frame.pack();

		//5. Show it.
		frame.setVisible(true);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		System.out.println("============ In ActionPerfromed ============");
		
	}
}
