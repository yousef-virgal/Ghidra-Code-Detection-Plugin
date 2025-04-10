package codeinjection;

public class OutputStringWrapper {
	String value;

	public OutputStringWrapper(String value) {
    	this.value = value;
    }
	
	public void setOutputString(String value) {
		this.value = value;
	}
	
    @Override
    public String toString() {
    	return this.value;
    }
}
