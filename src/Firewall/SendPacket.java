package Firewall;
import java.util.*;

public class SendPacket {
	
	
	public static void main(String[] args) {
		Scanner scan = new Scanner(System.in);
		Firewall fw = new Firewall(args[0]);
		
		try {
			while(true) {
				String dir = scan.next();
				
				if(dir.equals("quit")) {
					break;
				}
				
				String protocol = scan.next();
				Integer portNumber = scan.nextInt();
				String ipAddress = scan.next();
		        System.out.println(fw.accept_packet(dir, protocol, portNumber, ipAddress));
			}
		} catch (Exception e) {
			scan.close();
		}
		scan.close();
	}
}
