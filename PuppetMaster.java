
public class PuppetMaster {
	public static void main(String[] args) throws InterruptedException {
		System.out.println("Starting server...");
		Server server = new Server();
		server.runServer();
		System.out.println("Server Launched!");
	}
}
