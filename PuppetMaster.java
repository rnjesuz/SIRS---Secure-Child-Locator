static class PuppetMaster{

	Server server;
	List<Beacon> beaconList();
	
	public PuppetMaster(){
		SetUp();
	}
	
	private void SetUp(){
		
		System.Out.println("Insert Server Port.");
		int serverPort = Integer.ParseInt(Console.read());
		server = new Server(new String(localhost), serverPort);
		while(true){
			System.Out.println("Insert new Beacon Port");
			int beaconPort = Integer.parseInt(Console.read());
			beaconList.add(new Beacon(new String("localhost"), beaconPort));
		}
		
	}

}