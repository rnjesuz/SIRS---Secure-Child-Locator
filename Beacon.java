class Beacon{

	String ip;
	int port;
	
	public Beacon(String ip, int port, String username, String password){
		setIp(ip);
		setPort(port);
		setUsername(username);
		setPassword(password);
		
		ConnectToServer();
		SignUp();
		ImAliveCicle();
	}

	private void setIP(String ip){
		this.ip=ip;
	}
	
	private void setPort(int port){
		this.port=port;
	}
	
	private String getIp(String ip){
		return ip;
	}
	
	private int getPort(int port){
		return port;
	}
	
	private void ConnectToServer(){
		String ipToConnect=getIp();
		int portToConnect=getPort(); 
	}
	
	private SignUp(){
		String myUsername=getUsername();
		String myPassword=getPassword();
	}
	
	private void ImAliveCicle(){

	}
	
	
	
	
	
	
}