package Firewall;
import java.util.*;
import javafx.util.*;
import java.io.File;
import java.io.FileNotFoundException;

public class Firewall {
		
	// if the number of OCTETS increase in future, just increase NUM_OF_OCTETS
	private static final int NUM_OF_OCTETS = 4;
	
	// the rules are stored in a matrix, each row is for direction , column is for protocol, 
	// and each field stores list of <port range, ip address range>
	// thus, for each direction and protocol pair, there would be just one list of <port range, ip address range>
	private ArrayList<ArrayList<ArrayList <Pair<String, String>>>> protocolDirMatrix = 
			new ArrayList<ArrayList<ArrayList <Pair<String, String>>>>();
	
	Firewall(String loc) {
		
		init();
		
		File file = new File(loc);
		
		// parse each line of the file passed
		try {
			Scanner inputStream = new Scanner(file);
			while(inputStream.hasNext()){
				String data = inputStream.next();
				//parse and store the data
				buildFirewall(data);
			}
			inputStream.close();
		} catch (FileNotFoundException e){
            e.printStackTrace();
        }
		
	}
	
	// initialize the data structure by allocating memory for storing the rules specified
	void init() {
		for (int i = 0; i < Direction.values().length; i++) {
			ArrayList <ArrayList <Pair<String, String>>> outer = new  ArrayList <ArrayList <Pair<String, String>>>();
			for(int j = 0; j < Protocol.values().length; j++) {
				ArrayList <Pair<String, String>> inner = new ArrayList<Pair<String, String>>();
				outer.add(inner);
			}
			protocolDirMatrix.add(outer);
		}
	}
	
	// returns enum value of protocol
	// adding enum makes it easy to add more dir and protocols in future
	Protocol getProtocol(String protocol) {
		switch(protocol) {
			case "udp": {
				return Protocol.UDP;
			}
			case "tcp":{
				return Protocol.TCP;
			}
			default : {
				System.err.println("Invalid Protocol");
				return Protocol.INVALID;
			}
		}
	}
	
	//returns enum value of direction
	// adding enum makes it easy to add more dir and protocols in future
	Direction getDirection(String direction) {
		switch(direction) {
			case "inbound": {
				return Direction.INBOUND;
			}
			case "outbound": {
				return Direction.OUTBOUND;
			}
			default : {
				System.err.println("Invalid Direction");
				return Direction.INVALID;
			}
		}
	}
	
	// splits the each line of file passed and sets the fields of class Rule
	Rule getRule(String data) {
		String[] output = data.split(",");
		
		Rule rule = new Rule();
		
		// set direction
		Direction dir = getDirection(output[0]);
		rule.SetDir(dir);
	
		// set protocol
		Protocol protocol = getProtocol(output[1]);
		rule.SetProtocol(protocol);
	
		rule.SetPorts(output[2]);
		rule.SetIPAddress(output[3]);
		
		return rule;
	}
	
	// Called from constructor of class
	// stores all the rules by parsing the file
	void buildFirewall(String data) {		
		Rule rule = getRule(data);
		
		String portNumber = rule.getPorts();
		String address = rule.getAddress();
		int dir = rule.getDir().value;
		int protocol = rule.getProtocol().value;
		
		ArrayList <Pair<String, String>> portAddressList = protocolDirMatrix.get(dir).get(protocol);
		portAddressList.add(new Pair<String, String>(portNumber,address));
		
	}
	
	boolean isPortInRange(int start,int end, int portNumber) {
		if(portNumber >= start && portNumber <= end) {
			return true;
		}
		return false;
	}
	
	boolean isPortValueSame(int validPort, int portNumber) {
		if(validPort == portNumber) {
			return true;
		}
		return false;
	}
	
	boolean isAddressValSame(String validAddress, String address) {
		if(validAddress.equals(address)) {
			return true;
		}
		return false;
	}
	
	boolean isOctetInRange(String startSplit, String endSplit, String addressSplit) {
		if((Integer.parseInt(addressSplit) < Integer.parseInt(startSplit)) && 
				(Integer.parseInt(addressSplit) > Integer.parseInt(endSplit))) {
			return false;
		}
		
		return true;
	}
	
	boolean isAddressInRange(String start, String end, String address) {
		String[] startSplit = start.split("\\.");
		String[] endSplit = end.split("\\.");
		String[] addressSplit = address.split("\\.");
		
		for(int i = 0; i < NUM_OF_OCTETS; i++) {
			if (!isOctetInRange(startSplit[i], endSplit[i], addressSplit[i])) {
				return false;
			}
		}
		
		return true;
	}
	
	// checks if the port passed to accept_packet is a valid port
	boolean isValidPort(String validPorts, int portNumber) {
		
		// if '-' exists, it means it is in range
		if(validPorts.indexOf('-') != -1) {
			String[] output = validPorts.split("-");
			int start = Integer.parseInt(output[0]);
			int end = Integer.parseInt(output[1]);
			return isPortInRange(start,end, portNumber);
		} else {
			int validPort = Integer.parseInt(validPorts);
			return isPortValueSame(validPort, portNumber);
		}
	}
	
	// checks if the address passed to accept_packet is a valid address
	boolean isValidAddress(String validAddress, String address) {
		
		// if '-' exists, it means it is in range
		if(validAddress.indexOf('-') != -1) {
			String[] output = validAddress.split("-");
			String start = output[0];
			String end = output[1];
			return isAddressInRange(start, end, address);
		} else {
			return isAddressValSame(validAddress, address);
		}
	}
	
	// checks the validity of port and address specified
	boolean isPortAndAddressValid(ArrayList <Pair<String, String>> portAddressList, int portNumber, String address) {
		if (portAddressList.isEmpty()) {
			return false;
		}
		
		for(int i = 0; i < portAddressList.size(); i++) {
			String validPorts = portAddressList.get(i).getKey();
			String validAddress = portAddressList.get(i).getValue();
			
			if(!isValidPort(validPorts, portNumber)) {
				continue;
			}
			
			if(isValidAddress(validAddress, address)) {
				return true;
			}
		}
		
		return false;
	}
	
	boolean accept_packet(String dir, String protocol, int portNumber, String address) {
		
		// find enum values corresponding to dir and protocol
		// these enum values will be used for indexing the matrix of dir and protocol
		int dirIndex = 0;
		int protocolIndex = 0;
		switch(dir) {
			case "inbound" : {
				dirIndex = Direction.INBOUND.value;
				switch(protocol) {
					case "udp": {
						protocolIndex = Protocol.UDP.value;
						break;
					}
					case "tcp": {
						protocolIndex = Protocol.TCP.value;
						break;
					}
					default: {
						return false;
					}
				}
				break;
			}
			case "outbound" : {
				dirIndex = Direction.OUTBOUND.value;
				switch(protocol) {
					case "udp": {
						protocolIndex = Protocol.UDP.value;
						break;
					}
					case "tcp": {
						protocolIndex = Protocol.TCP.value;
						break;
					}
					default: {
						return false;
					}
				}
				break;
			}
			default: {
				return false;
			}
		}
		
		// find the list of port and address corresponding to the direction and protocol specified
		ArrayList <Pair<String, String>> portAddressList = protocolDirMatrix.get(dirIndex).get(protocolIndex);
		
		// check if port and address specified are valid and match with any rule in the list of port and address
		return isPortAndAddressValid(portAddressList, portNumber, address);
	}
}
