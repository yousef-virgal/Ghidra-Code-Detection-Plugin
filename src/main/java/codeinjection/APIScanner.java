package codeinjection;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;

public class APIScanner {
	
	 private final Program program;
	 
	 public ArrayList<APIScannerResults> results = new ArrayList<APIScannerResults>();
	 
	 private static final String[] INJECTION_APIS = {
	        "WriteProcessMemory", "NtWriteVirtualMemory",
	        "CreateRemoteThread", "NtCreateThreadEx",
	        "QueueUserAPC", "RtlCreateUserThread",
	        "VirtualAllocEx", "VirtualProtectEx"
	    };

	    public APIScanner(Program program) {
	        this.program = program;
	    }

	    public void scan(TaskMonitor monitor) {
	    	
	        FunctionManager functionManager = program.getFunctionManager();
	        for (Function function : functionManager.getFunctions(true)) {
	            if (monitor.isCancelled()) break;
	            checkFunctionForInjectionAPI(function);
	        }
	    }

	    private void checkFunctionForInjectionAPI(Function function) {
	        String functionName = function.getName();
	        if (Arrays.stream(INJECTION_APIS).anyMatch(functionName::contains)) {
	            markAsSuspicious(functionName, function.getEntryPoint());
	        }
	    }

	    private void markAsSuspicious(String name, Address address) {
	        // Implement your marking logic (e.g., set bookmark)
	    	Msg.debug(this, "Address marked as Suspicious by API Scanner " + address.toString());
	        program.getBookmarkManager().setBookmark(address, "Suspicious", "INJECTION_API", "");
	        
	        results.add(new APIScannerResults(name, address));
	    }
}
