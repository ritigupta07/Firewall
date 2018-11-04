package Firewall;

// stores the rule for each line specified in csv file
public class Rule {
	private Direction dir;
	private Protocol protocol;
	private String ports;
	private String ipAddress;
	
	public void SetDir(Direction dir) {
		this.dir = dir;
	}
	
	public void SetProtocol(Protocol protocol) {
		this.protocol = protocol;
	}
	
	public void SetPorts(String ports) {
		this.ports = ports;
	}
	
	public void SetIPAddress(String address) {
		this.ipAddress = address;
	}
	
	public Direction getDir() {
		return dir;
	}
	
	public Protocol getProtocol() {
		return protocol;
	}
	
	public String getPorts() {
		return ports;
	}
	
	public String getAddress() {
		return ipAddress;
	}
}
