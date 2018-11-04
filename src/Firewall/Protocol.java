package Firewall;

// add more protocols in future
public enum Protocol {
	INVALID(-1),TCP(0),UDP(1);
	public final int value;
	private Protocol(int value){
        this.value = value;
    }
}
