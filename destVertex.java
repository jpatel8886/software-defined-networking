package edu.wisc.cs.sdn.apps.l3routing;

public class destVertex {

	public int distance;
	public long prevID;
	public int prevPort;
	

	public destVertex (int distance, long prevID) {
		this.distance = distance;
		this.prevID = prevID;
	}

	public void setDistance (int distance) {
		this.distance = distance;
	}

	public void setPrevId (long prevID) {
		this.prevID = prevID;
	}

	public void setPrevPort (int prevPort) {
		this.prevPort = prevPort;
	}

	public int getDistance() {
		return this.distance;
	}

	public long getPrevId() {
		return this.prevID;
	}

	public int getPrevPort() {
		return this.prevPort;
	}

	@Override 
	public String toString(){
		return "distance: "+ distance + "\n prevId: " + prevID + "\n prevPort: "+ prevPort;
	}

}












