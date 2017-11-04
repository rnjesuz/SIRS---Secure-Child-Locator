class Server(){

	private String ip;
	private int port;

	public Server(String ip, int port){
		setIP(ip);
		setPort(port);
		Cicle();
		
	}

	private void SetIp(String ip){
		this.ip=ip;
	}
	
	private void SetPort(int port){
		this.port=port;
	}
	
	private String GetIP(){
		return ip;
	}
	
	private int GetPort(){
		return port;
	}
	
	private Cicle(){
	
	}


	
}