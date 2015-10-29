
import java.io.*;
import java.math.BigInteger;
import javax.net.ssl.*;
import java.security.*;
import java.util.HashMap;

public class CLAServer {
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8188;
	static final String KEYSTORE = "LIUkeystore.ks";
	static final String TRUSTSTORE = "LIUtruststore.ks";
	static final String trustSTOREPASSWD = "abcdef";
	static final String keySTOREPASSWD = "123456";
	static final String ALIASPASSWD = keySTOREPASSWD;
	
	// Inner class VoterPublicKey
	public class VoterPublicKey {
		private String ssn;
		private BigInteger e, n;
		
		VoterPublicKey( BigInteger e, BigInteger n, String ssn){
			this.ssn = ssn;
			this.n = n;
			this.e = e;
		}

		public BigInteger getE(){
			return this.e;
		}
		public BigInteger getN(){
			return this.n;
		}
		public String getSSN(){
			return this.ssn;
		}
	}
	
	// Hash map containing valid voter social security numbers and their corresponding public keys
	HashMap<String, VoterPublicKey> voterPublicKeys;	// <ssn, voterPublicKey>
	HashMap<String, String> voterValidationCodes;		// <ssn, validationCode>

	/** Constructor
	 * @param port The port where the server will listen for requests
	 */
	CLAServer( int port )
	{
		this.port = port;
		
		// Set up valid voters
		voterPublicKeys = new HashMap<String, VoterPublicKey>();
		voterPublicKeys.put("123", new VoterPublicKey(new BigInteger("17"), new BigInteger("551"), "123"));
		voterPublicKeys.put("456", new VoterPublicKey(new BigInteger("7"), new BigInteger("253"), "456"));
		voterPublicKeys.put("789", new VoterPublicKey(new BigInteger("5"), new BigInteger("119"), "789"));
		
		// Set up validation keys
		voterValidationCodes = new HashMap<String, String>();
	}
	
	/**
	 * Function run certifies/authenticates voter client, starts the server and processes SSN input
	 */
	public void run()
	{
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
			SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket( port );
			sss.setEnabledCipherSuites( sss.getSupportedCipherSuites() );
			
			// Client authentication
			sss.setNeedClientAuth(true);
			
			System.out.println("\n>>>> CLA Server: active ");
			SSLSocket incoming = (SSLSocket)sss.accept();

			BufferedReader in = new BufferedReader( new InputStreamReader( incoming.getInputStream() ) );
			PrintWriter out = new PrintWriter( incoming.getOutputStream(), true );			
			
			// ===== Secure election ===== //
			
			String ssn = in.readLine();
			System.out.println("Server received SSN " + ssn + " from client");
			String validationCode = "";
			
			// Check if the ssn is valid
			if(voterPublicKeys.containsKey(ssn))
			{
				// check if a validation number already has been created for this ssn
				if(voterValidationCodes.containsKey(ssn))
				{
					// get the value of key 'ssn'
					validationCode = voterValidationCodes.get(ssn);
				} else {
					// create a random validationCode
					validationCode = generatevalidationCode();
					voterValidationCodes.put(ssn, validationCode);
					// only used to show what is saved and to whom.
					createASaveFile(voterValidationCodes);
					
				}
				
				// Print the validation number back to the voter client
				out.println(validationCode);
				System.out.println("Sending validation code " + validationCode + " to the client");
				
			} else {
				// Not a valid ssn
				System.out.println(ssn + " is not a valid ssn!");
				out.println(ssn + " is not a valid ssn!");
			}

			incoming.close();
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}
	
	private void createASaveFile(HashMap<String, String> voterValidationCodes2) {
		// TODO Auto-generated method stub
		File file = new File("CLA_voters_and_codes.txt");
		BufferedWriter writer;
		try {
			writer = new BufferedWriter(new FileWriter(file));
			writer.write(voterValidationCodes2.toString());
			writer.close();
		} catch (IOException e) {
			
		}
		
	}

	/*
	 * Generate a random validation number.
	 */
	private String generatevalidationCode()
	{
		int randomInt = (int) Math.round( Math.random() * 20000);
		return Integer.toString(randomInt);
	}

	/** main method of class
	 * @param args[0] Optional port number in place of
	 *        the default
	 */
	public static void main( String[] args ) {
		int port = DEFAULT_PORT;
		if (args.length > 0 ) {
			port = Integer.parseInt( args[0] );
		}
		CLAServer CLAServer = new CLAServer( port );
		CLAServer.run();
	}
}

