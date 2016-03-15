//author: Nagabhushan S Baddi 
//WhoisGUI is a Whois client that can use for queries for persons, domain, ASN, network, etc 

import java.net.*;
import java.io.*;

public class WhoisQuery {

	public final static int DEFAULT_PORT = 43;
	public final static String DEFAULT_HOST = "whois.internic.net";

	private int defaultPort = DEFAULT_PORT;
	private InetAddress myHost;

	public WhoisQuery(InetAddress host, int port) {
		this.myHost = host;
		this.defaultPort = port;
	}

	public WhoisQuery(InetAddress host) {
		this(host, DEFAULT_PORT);
	}

	public WhoisQuery(String hostName, int myPort) throws UnknownHostException {
		this(InetAddress.getByName(hostName), myPort);
	}

	public WhoisQuery(String hostName) throws UnknownHostException {
		this(InetAddress.getByName(hostName), DEFAULT_PORT);
	}

	public WhoisQuery() throws UnknownHostException {
		this(DEFAULT_HOST, DEFAULT_PORT);
	}

	// Items to search for
	public enum SearchFor {
		ANY("Any"), NETWORK("Network"), PERSON("Person"), HOST("Host"), DOMAIN("Domain"), ORGANIZATION(
				"Organization"), GROUP("Group"), GATEWAY("Gateway"), ASN("ASN");

		private String label;

		private SearchFor(String label) {
			this.label = label;
		}
	}

	// Categories to search in
	public enum SearchIn {
		ALL(""), NAME("Name"), MAILBOX("Mailbox"), HANDLE("!");

		private String label;

		private SearchIn(String label) {
			this.label = label;
		}
	}

	public String lookUpNames(String target, SearchFor category, SearchIn group, boolean exactMatch)
			throws IOException {

		String suffix = "";
		if (!exactMatch)
			suffix = ".";

		String prefix = category.label + " " + group.label;
		String query = prefix + target + suffix;

		Socket socket = new Socket();
		try {
			SocketAddress address = new InetSocketAddress(myHost, defaultPort);
			socket.connect(address);
			Writer out = new OutputStreamWriter(socket.getOutputStream(), "ASCII");
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "ASCII"));
			out.write(query + "\r\n");
			out.flush();

			StringBuilder response = new StringBuilder();
			String theLine = null;
			while ((theLine = in.readLine()) != null) {
				response.append(theLine);
				response.append("\r\n");
			}
			return response.toString();
		} finally {
			socket.close();
		}
	}

	public InetAddress getHost() {
		return this.myHost;
	}

	public void setHost(String host) throws UnknownHostException {
		this.myHost = InetAddress.getByName(host);
	}
}