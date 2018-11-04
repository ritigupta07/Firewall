package Firewall;

//add more directions in future
public enum Direction {
	INVALID(-1), INBOUND(0) , OUTBOUND(1);
	public final int value;
	private Direction(int value){
        this.value = value;
    }
}
