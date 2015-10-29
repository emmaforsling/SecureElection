
import java.io.*;
import java.math.BigInteger;
import javax.net.ssl.*;

import java.security.*;
import java.util.HashMap;

public class CTFServer {
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "LIUkeystore.ks";
	static final String TRUSTSTORE = "LIUtruststore.ks";
	static final String trustSTOREPASSWD = "abcdef";
	static final String keySTOREPASSWD = "123456";
	static final String ALIASPASSWD = keySTOREPASSWD;

	// Inner class VotingResult
		public class VotingResult {
			private String key;
			private int result;
			
			VotingResult( int result, String key){
				this.key = key;
				this.result = result;
			}

			public int getResult(){
				return this.result;
			}
			public String getKey(){
				return this.key;
			}
		}
	HashMap<String, Integer> VotingResults;	// <ssn, voterPublicKey>
	
	/** Constructor
	 * @param port The port where the server will listen for requests
	 */
	CTFServer( int port )
	{
		this.port = port;
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
			
			System.out.println("\n>>>> CTF Server: active ");
			SSLSocket incoming = (SSLSocket)sss.accept();

			BufferedReader in = new BufferedReader( new InputStreamReader( incoming.getInputStream() ) );
			PrintWriter out = new PrintWriter( incoming.getOutputStream(), true );			
			
			// ===== Secure election ===== //
			
			String valCode = in.readLine();
			
			// Skapa connection med CLA Server för att kolla om valCode är giltig.
			
			// do stuff here
			System.out.println("Received validation code " + valCode + " from the client");
			
			String chosenParty = "Party1";//in.readLine();
			updateAndSaveResult(chosenParty);
			// 
			
			incoming.close();
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}

	private void updateAndSaveResult(String chosenParty) {
		// kalla på en funktion som läser in en fil med tidigare valresultat.
		BufferedReader br;
		String everything = "";
		try {
			br = new BufferedReader(new FileReader("Results.txt"));
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();

		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		    }
		    everything = sb.toString();
		    br.close();
		} catch (IOException e) {
			//out.println(e.toString());
		}
		
		int resultParty1 = 0;
		int resultParty2 = 0;
		int resultParty3 = 0;
		
		String temp = everything.replace("{","");	//remove character {
		temp = temp.replace("}","");				//remove character }
		temp = temp.replaceAll("\\s","");			//removes white space
		String[] temp2 = temp.split(",");			//split it
		for(int i = 0; i<temp2.length;++i){
			String[] tmp = temp2[i].split("=");		//split it again
			if(tmp[0].equals("Party1")){
				resultParty1 = Integer.parseInt(tmp[1]);
			} else if(tmp[0].equals("Party2")){
				resultParty2 = Integer.parseInt(tmp[1]);
			} else if(tmp[0].equals("Party3")){
				resultParty3 = Integer.parseInt(tmp[1]);
			} else {
				System.out.println("==="+ tmp[0] + "===");
			}
		}
		if(chosenParty.equals("Party1")){
			resultParty1++;
		} else if(chosenParty.equals("Party2")){
			resultParty2++;
		} else if(chosenParty.equals("Party3")){
			resultParty3++;
		} else {
			System.out.println("CTF, updateAndSaveResults - Choosen party is unkown");
		}
		VotingResults = new HashMap<String, Integer>();
		VotingResults.put("Party1",resultParty1);
		VotingResults.put("Party2",resultParty2);
		VotingResults.put("Party3",resultParty3);
		
		// updatera denna med att öka på ett för valt parti
		saveVotingResults(VotingResults);
		
	}

	private void saveVotingResults(HashMap<String, Integer> votingResults2) {
		File file = new File("Results.txt");
		BufferedWriter writer;
		try {
			writer = new BufferedWriter(new FileWriter(file));
			writer.write(VotingResults.toString());
			writer.close();
		} catch (IOException e) {
			
		}
	
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
		CTFServer CTFServer = new CTFServer( port );
		CTFServer.run();
	}
}

