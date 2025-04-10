package codeinjection;

import ghidra.program.model.address.Address;

public class APIScannerResults {
	public String apiCall;
	public Address address;
	
	public APIScannerResults(String apiCall, Address address) {
		this.apiCall = apiCall;
		this.address = address ;
	}
	
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return this.apiCall + " API call is being made at " + this.address; 
	}
}
