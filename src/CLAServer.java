
// An example class that uses the secure server socket class

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.util.StringTokenizer;

public class CLAServer {
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "LIUkeystore.ks";
	static final String TRUSTSTORE = "LIUtruststore.ks";
	static final String trustSTOREPASSWD = "abcdef";
	static final String keySTOREPASSWD = "123456";
	static final String ALIASPASSWD = keySTOREPASSWD;
	
	String command = "";
	String filename = "";
	String voter = "";
	StringBuilder filecontents = new StringBuilder("");
	int filecontentsLength = -1;

	/** Constructor
	 * @param port The port where the server
	 *    will listen for requests
	 */
	CLAServer( int port ) {
		this.port = port;
	}
	
	/** The method that does the work for the class */
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
			SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket( port );
			sss.setEnabledCipherSuites( sss.getSupportedCipherSuites() );
			
			// Client authentication
			sss.setNeedClientAuth(true);
			
			System.out.println("\n>>>> SecureAdditionServer: active ");
			SSLSocket incoming = (SSLSocket)sss.accept();

			BufferedReader in = new BufferedReader( new InputStreamReader( incoming.getInputStream() ) );
			PrintWriter out = new PrintWriter( incoming.getOutputStream(), true );			
			
			// Command
			String str;
			while ( !(str = in.readLine()).equals("") )
			{
				if(command.equals("")) {
					command = str;
				} else if(voter.equals("")) {
					voter = str;
				}
//				if(command.equals(""))
//				{
//					command = str;
//				} else if(filename.equals(""))
//				{
//					filename = str;
//					if(command.equals("download")){
//						download(filename, out);
//						reset();
//					}
//					if(command.equals("delete")){
//						delete(filename, out);
//						reset();
//					}
//				} else if(filecontentsLength == -1) {
//					// set the filecontentsLength
//					filecontentsLength = Integer.parseInt(str);
//					// for the StringBuilder fileContents, ensure that it is big enough
//					filecontents.ensureCapacity(filecontentsLength);
//				} else if(filecontentsLength > filecontents.length()){
//					filecontents.append(str);
//					if(filecontents.length() >= filecontentsLength && command.equals("upload")){
//						upload(filename, filecontentsLength, filecontents, out);
//						reset();
//					}
//				} 
			}
			incoming.close();
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}
	
	private void reset(){
		command = "";
		filename = "";
		filecontents.delete(0, filecontents.length());
		filecontentsLength = -1;
	}
	
	private void download(String filename, PrintWriter out)
	{	
		StringBuilder sb=new StringBuilder();
		try (BufferedReader reader = new BufferedReader(new FileReader(filename)))
		{
			String line;
			while((line=reader.readLine()) != null)
			{
				sb.append(line).append('\n');
			}
			sb.deleteCharAt(sb.length() - 1);
			reader.close();
		}
		catch(FileNotFoundException exception)
		{
			out.println(exception.toString());
		}
		catch(IOException exception)
		{
			out.println(exception.toString());
		}
		
		out.println(filename + " downloaded, contents: " + sb.toString());
	}
	
	private void delete(String filename, PrintWriter out)
	{
		File file = new File(filename);
		if(file.delete())
		{
			out.println(filename + " deleted.");
		} else {
			out.println("File not found.");
		}
	}

	private void upload(String filename, int fileLength, StringBuilder filecontents, PrintWriter out)
	{
		File file = new File(filename);
		BufferedWriter writer;
		try {
			writer = new BufferedWriter(new FileWriter(file));
			writer.write(filecontents.toString());
			writer.close();
		} catch (IOException e) {
			out.println(e.toString());
		}
		out.println(filename + " uploaded");
	}

	/** The test method for the class
	 * @param args[0] Optional port number in place of
	 *        the default
	 */
	public static void main( String[] args ) {
		int port = DEFAULT_PORT;
		if (args.length > 0 ) {
			port = Integer.parseInt( args[0] );
		}
		CLAServer addServe = new CLAServer( port );
		addServe.run();
	}
}

