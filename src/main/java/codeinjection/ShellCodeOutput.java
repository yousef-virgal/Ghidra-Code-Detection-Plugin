package codeinjection;

import ghidra.program.model.address.Address;

public class ShellCodeOutput {
	public int score;
	public Address startAddress;

	public ShellCodeOutput(int score, Address startAdress) {
		this.score = score;
		this.startAddress = startAdress;
	}

	@Override
	public String toString() {
		return "Detected Shell Code at address" + this.startAddress.toString() + " with confidence score of "
				+ this.score;
	}
}
