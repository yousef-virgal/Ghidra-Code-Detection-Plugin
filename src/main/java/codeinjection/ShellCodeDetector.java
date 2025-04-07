package codeinjection;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class ShellCodeDetector {
	private final Program program;
    private static final byte[][] SHELLCODE_PATTERNS = {
        { (byte)0xE8, 0x00, 0x00, 0x00, 0x00 },  // CALL rel32
        { (byte)0xFF, (byte)0xD0 },              // CALL EAX
        { (byte)0x68, 0x00, 0x00, 0x00, 0x00, (byte)0xC3 } // PUSH + RET
    };

    public ShellCodeDetector(Program program) {
        this.program = program;
    }

    public void analyze(TaskMonitor monitor) {
        Memory memory = program.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (monitor.isCancelled()) break;
            if (!block.isExecute()) { // Focus on non-executable regions
                scanBlockForShellcode(block, monitor);
            }
        }
    }

    private void scanBlockForShellcode(MemoryBlock block, TaskMonitor monitor) {
        try {
            byte[] data = new byte[(int) block.getSize()];
            int bytesRead = program.getMemory().getBytes(block.getStart(), data);
           
            if (bytesRead > 0) {
                for (byte[] pattern : SHELLCODE_PATTERNS) {
                    int offset = findPattern(data, pattern);
                    if (offset != -1) {
                        Address foundAt = block.getStart().add(offset);
                        markAsShellcode(foundAt);
                    }
                }
            }
        } catch (Exception e) {
        	Msg.debug(this, "Error Occured");
        	Msg.debug(this, e.getMessage());
            // Handle memory read errors
        }
    }

    private int findPattern(byte[] data, byte[] pattern) {
        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (pattern[j] != 0x00 && data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    private void markAsShellcode(Address address) {
    	Msg.debug(this, "Address Detected by Shell Code" + address.toString());
        // Implement your marking logic (e.g., set background color)
    	program.getBookmarkManager().setBookmark(address, "Suspicious", "Shell Code", "AAA");
        program.getListing().setComment(address, CodeUnit.EOL_COMMENT, "SHELLCODE");
    }
}
