package codeinjection;

import java.util.ArrayList;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


enum SignatureType {
    CRITICAL,   
    HIGH,       
    MEDIUM,     
    LOW,       
    VERY_LOW    
}


public class ShellCodeDetector {
	 private Program program = null;
	 public ArrayList<ShellCodeOutput> results = new ArrayList<ShellCodeOutput>(); 
	  
	    private static final ShellcodeSignature[] PRIMARY_SIGNATURES = {
	        new ShellcodeSignature(
	            new byte[] { (byte)0xE8, 0x00, 0x00, 0x00, 0x00 },           
	            "GetEIP via CALL $+5",
	            SignatureType.CRITICAL
	        ),
	        new ShellcodeSignature(
	            new byte[] { (byte)0xEB, 0x03, (byte)0x5E, (byte)0xEB, 0x05 }, 
	            "GetEIP via JMP/POP technique",
	            SignatureType.CRITICAL
	        ),
	        new ShellcodeSignature(
	            new byte[] { (byte)0xD9, (byte)0xEE, (byte)0xD9, 0x74, 0x24 }, 
	            "GetEIP via FPU instructions",
	            SignatureType.CRITICAL
	        ),
	        
	        new ShellcodeSignature(
	            new byte[] { (byte)0xB9, 0x00, 0x00, 0x00, 0x00, (byte)0x31, 0x00, (byte)0x80 },
	            "XOR decoder loop",
	            SignatureType.HIGH
	        ),
	        new ShellcodeSignature(
	            new byte[] { (byte)0xE2, (byte)0xFA },                        
	            "Decoder LOOP instruction",
	            SignatureType.MEDIUM
	        ),
	        
	        new ShellcodeSignature(
	            new byte[] { 0x54, 0x68, 0x73, 0x73, 0x00, 0x00 },            
	            "API resolution string push",
	            SignatureType.MEDIUM
	        ),
	        new ShellcodeSignature(
	            new byte[] { 0x5B, (byte)0x89, (byte)0xE5, (byte)0x81 },      
	            "PEB access sequence",
	            SignatureType.HIGH
	        ),
	        
	       
	        new ShellcodeSignature(
	            new byte[] { (byte)0xCD, 0x2E },                             
	            "INT 0x2E syscall",
	            SignatureType.HIGH
	        ),
	        new ShellcodeSignature(
	            new byte[] { 0x0F, 0x34 },                                    
	            "SYSENTER syscall",
	            SignatureType.HIGH
	        ),
	        
	  
	        new ShellcodeSignature(
	            new byte[] { 0x6A, 0x01, 0x6A, 0x02, 0x6A, 0x06 },           
	            "Socket creation",
	            SignatureType.MEDIUM
	        ),
	        
	      
	        new ShellcodeSignature(
	            new byte[] { (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0x90 },
	            "NOP sled",
	            SignatureType.LOW
	        ),
	        new ShellcodeSignature(
	            new byte[] { (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC },
	            "INT3 padding",
	            SignatureType.LOW
	        )
	    };
	    
	    private static final ShellcodeSignature[] SECONDARY_SIGNATURES = {
	     
	        new ShellcodeSignature(
	            new byte[] { 0x31, (byte)0xC0 },                              
	            "Register zeroing",
	            SignatureType.VERY_LOW
	        ),
	        new ShellcodeSignature(
	            new byte[] { (byte) 0x89, (byte)0xE5 },                              
	            "Stack frame setup",
	            SignatureType.VERY_LOW
	        ),
	        new ShellcodeSignature(
	            new byte[] { (byte)0xFF, (byte)0xE4 },                        
	            "JMP ESP",
	            SignatureType.LOW
	        )
	    };
	    
	    private static final String[] SUSPICIOUS_STRINGS = {
	        "cmd.exe", "powershell", "wsock32", "ws2_32", "kernel32", "CreateProcess",
	        "VirtualAlloc", "WriteProcessMemory", "explorer.exe", "cmd /c", "calc.exe"
	    };
	    
	 
	    private static final int CRITICAL_CONFIDENCE_SCORE = 100;
	    private static final int HIGH_CONFIDENCE_SCORE = 80;
	    private static final int MEDIUM_CONFIDENCE_SCORE = 50;
	    private static final int LOW_CONFIDENCE_SCORE = 30;
	    
	    private static final int PRIMARY_PROXIMITY_THRESHOLD = 64; 
	    private static final int EXTENDED_PROXIMITY_THRESHOLD = 256; 
	    
	    private static final int MIN_ENTROPY_ANALYSIS_SIZE = 20;
	    
	    
	    public ShellCodeDetector(Program program) {
	        this.program = program;
	    }

	    public void analyze(TaskMonitor monitor) throws CancelledException {
	        Memory memory = program.getMemory();
	        monitor.setMessage("Scanning for shellcode signatures...");
	        
	        List<ShellcodeMatch> allMatches = new ArrayList<>();
	        
	        int totalBlocks = 0;
	        for (MemoryBlock block : memory.getBlocks()) {
	            totalBlocks++;
	        }
	        
	        int blockCount = 0;
	        for (MemoryBlock block : memory.getBlocks()) {
	            blockCount++;
	            
	            if (monitor.isCancelled()) {
	                throw new CancelledException();
	            }
	            
	            monitor.setProgress((int)((blockCount * 100) / totalBlocks));  
	            
	            boolean isInteresting = (!block.isExecute() && block.isWrite()) || 
	                                   block.getName().toLowerCase().contains("stack") ||
	                                   block.getName().toLowerCase().contains("heap");
	            
	            if (isInteresting && block.getSize() > 10) {
	                monitor.setMessage("Scanning block: " + block.getName() + " (" + blockCount + "/" + totalBlocks + ")");
	                List<ShellcodeMatch> blockMatches = scanBlockForShellcode(block, monitor);
	                allMatches.addAll(blockMatches);
	            }
	        }
	        
	        analyzeMatches(allMatches, monitor);
	    }

	    private List<ShellcodeMatch> scanBlockForShellcode(MemoryBlock block, TaskMonitor monitor) throws CancelledException {
	        List<ShellcodeMatch> matches = new ArrayList<>();
	        
	        try {
	            if (block.getSize() > Integer.MAX_VALUE) {
	                Msg.warn(this, "Block too large to scan fully: " + block.getName() + ", truncating scan");
	                return scanLargeBlock(block, monitor);
	            }
	            
	            byte[] data = new byte[(int) block.getSize()];
	            int bytesRead = program.getMemory().getBytes(block.getStart(), data);
	            
	            if (bytesRead <= 0) {
	                return matches;
	            }
	            
	            for (ShellcodeSignature signature : PRIMARY_SIGNATURES) {
	                if (monitor.isCancelled()) {
	                    throw new CancelledException();
	                }
	                
	                List<Integer> offsets = findAllPatternMatches(data, signature.pattern);
	                for (int offset : offsets) {
	                    Address foundAt = block.getStart().add(offset);
	                    matches.add(new ShellcodeMatch(foundAt, signature.description, signature.type));
	                }
	            }
	            
	            if (!matches.isEmpty()) {
	                for (ShellcodeSignature signature : SECONDARY_SIGNATURES) {
	                    if (monitor.isCancelled()) {
	                        throw new CancelledException();
	                    }
	                    
	                    List<Integer> offsets = findAllPatternMatches(data, signature.pattern);
	                    for (int offset : offsets) {
	                        Address foundAt = block.getStart().add(offset);
	                        matches.add(new ShellcodeMatch(foundAt, signature.description, signature.type));
	                    }
	                }
	                
	               
	                for (String suspiciousString : SUSPICIOUS_STRINGS) {
	                    byte[] stringBytes = suspiciousString.getBytes();
	                    List<Integer> offsets = findAllPatternMatches(data, stringBytes);
	                    for (int offset : offsets) {
	                        Address foundAt = block.getStart().add(offset);
	                        matches.add(new ShellcodeMatch(foundAt, "Suspicious string: " + suspiciousString, 
	                                                    SignatureType.MEDIUM));
	                    }
	                }
	                
	                if (matches.size() > 0 && data.length >= MIN_ENTROPY_ANALYSIS_SIZE) {
	                    double entropy = calculateEntropy(data);
	                    
	                    if (entropy > 6.8) { 
	                        matches.add(new ShellcodeMatch(block.getStart(), 
	                                                     "High entropy region (" + String.format("%.2f", entropy) + ")",
	                                                     SignatureType.MEDIUM));
	                    }
	                    
	                    int validInstructionSequences = analyzeInstructionDensity(block);
	                    if (validInstructionSequences > 5) {
	                        matches.add(new ShellcodeMatch(block.getStart(),
	                                                     "High instruction density in data segment",
	                                                     SignatureType.MEDIUM));
	                    }
	                }
	            }
	            
	        } catch (MemoryAccessException e) {
	            Msg.error(this, "Error reading memory at block " + block.getName() + ": " + e.getMessage());
	        }
	        
	        return matches;
	    }
	    
	    private List<ShellcodeMatch> scanLargeBlock(MemoryBlock block, TaskMonitor monitor) throws CancelledException {
	        List<ShellcodeMatch> matches = new ArrayList<>();
	        
	        long remainingSize = block.getSize();
	        long offset = 0;
	        int chunkSize = 10 * 1024 * 1024;
	        
	        while (remainingSize > 0 && !monitor.isCancelled()) {
	            int currentChunkSize = (int) Math.min(remainingSize, chunkSize);
	            byte[] data = new byte[currentChunkSize];
	            
	            try {
	                Address chunkStart = block.getStart().add(offset);
	                program.getMemory().getBytes(chunkStart, data);
	                
	                for (ShellcodeSignature signature : PRIMARY_SIGNATURES) {
	                    List<Integer> chunkOffsets = findAllPatternMatches(data, signature.pattern);
	                    for (int chunkOffset : chunkOffsets) {
	                        Address foundAt = chunkStart.add(chunkOffset);
	                        matches.add(new ShellcodeMatch(foundAt, signature.description, signature.type));
	                    }
	                }
	                
	            } catch (MemoryAccessException e) {
	                Msg.error(this, "Error reading memory chunk at " + block.getStart().add(offset) + ": " + e.getMessage());
	            }
	            
	            offset += currentChunkSize;
	            remainingSize -= currentChunkSize;
	            monitor.setProgress((int)((offset * 100) / block.getSize()));
	        }
	        
	        return matches;
	    }
	    
	    private List<Integer> findAllPatternMatches(byte[] data, byte[] pattern) {
	        List<Integer> matches = new ArrayList<>();
	        
	        outer:
	        for (int i = 0; i <= data.length - pattern.length; i++) {
	            for (int j = 0; j < pattern.length; j++) {
	                if (pattern[j] != 0x00 && data[i + j] != pattern[j]) {
	                    continue outer;
	                }
	            }
	            matches.add(i);
	        }
	        
	        return matches;
	    }
	    
	     private double calculateEntropy(byte[] data) {
	        int[] frequencies = new int[256];
	        
	         for (byte b : data) {
	            frequencies[b & 0xFF]++;
	        }
	        
	        double entropy = 0;
	        for (int freq : frequencies) {
	            if (freq > 0) {
	                double probability = (double) freq / data.length;
	                entropy -= probability * (Math.log(probability) / Math.log(2));
	            }
	        }
	        
	        return entropy;
	    }
	    
	    private int analyzeInstructionDensity(MemoryBlock block) {
	        int validSequences = 0;
	        
	        try {
	             
	            byte[] testBytes = new byte[Math.min(1024, (int)block.getSize())];
	            program.getMemory().getBytes(block.getStart(), testBytes);
	            
	            int consecutiveValidInstructions = 0;
	            int potentialJumpTargets = 0;
	            
	            for (int i = 0; i < testBytes.length - 5; i++) {
	                if ((testBytes[i] & 0xFF) == 0x55 && (testBytes[i+1] & 0xFF) == 0x8B && 
	                    (testBytes[i+2] & 0xFF) == 0xEC) {
	                    consecutiveValidInstructions += 2;
	                    potentialJumpTargets++;
	                }
	                
	                if ((testBytes[i] & 0xFF) == 0x8B && (testBytes[i+1] & 0xFF) >= 0x40 && 
	                    (testBytes[i+1] & 0xFF) <= 0x5F) {
	                    consecutiveValidInstructions++;
	                }
	                
	                if ((testBytes[i] & 0xFF) == 0xFF && ((testBytes[i+1] & 0xFF) == 0xD0 || 
	                    (testBytes[i+1] & 0xFF) == 0xD1 || (testBytes[i+1] & 0xFF) == 0xD2 || 
	                    (testBytes[i+1] & 0xFF) == 0xD3)) {
	                    consecutiveValidInstructions++;
	                    potentialJumpTargets++;
	                }
	            }
	             
	            validSequences = consecutiveValidInstructions + potentialJumpTargets;
	            
	        } catch (Exception e) {
	            Msg.debug(this, "Error in instruction density analysis: " + e.getMessage());
	        }
	        
	        return validSequences;
	    }
	    
	    
	    private void analyzeMatches(List<ShellcodeMatch> matches, TaskMonitor monitor) throws CancelledException {
	        if (matches.size() < 2) {
	            return;  
	        }
	        
	       matches.sort((a, b) -> a.address.compareTo(b.address));
	        
	        List<ShellcodeCluster> clusters = formClusters(matches, monitor);
	        
	        for (ShellcodeCluster cluster : clusters) {
	            if (monitor.isCancelled()) {
	                throw new CancelledException();
	            }
	            
	            int confidenceScore = calculateClusterConfidence(cluster);
	            
	            if (confidenceScore >= MEDIUM_CONFIDENCE_SCORE) {
	                markClusterAsShellcode(cluster, confidenceScore, monitor);
	            }
	        }
	    }
	    
	    private List<ShellcodeCluster> formClusters(List<ShellcodeMatch> matches, TaskMonitor monitor) 
	            throws CancelledException {
	        List<ShellcodeCluster> clusters = new ArrayList<>();
	        List<ShellcodeMatch> currentCluster = new ArrayList<>();
	        
	        for (int i = 0; i < matches.size(); i++) {
	            if (monitor.isCancelled()) {
	                throw new CancelledException();
	            }
	            
	            ShellcodeMatch current = matches.get(i);
	            
	            if (currentCluster.isEmpty()) {
	                currentCluster.add(current);
	            } else {
	                ShellcodeMatch prev = currentCluster.get(currentCluster.size() - 1);
	                long distance = current.address.subtract(prev.address);
	                
	                if (distance <= PRIMARY_PROXIMITY_THRESHOLD) {
	                    currentCluster.add(current);
	                } else {
	                    if (currentCluster.size() >= 2) {
	                        clusters.add(new ShellcodeCluster(new ArrayList<>(currentCluster)));
	                    }
	                    currentCluster.clear();
	                    currentCluster.add(current);
	                }
	            }
	        }
	        
	        if (currentCluster.size() >= 2) {
	            clusters.add(new ShellcodeCluster(new ArrayList<>(currentCluster)));
	        }
	        
	        mergeClusters(clusters);
	        
	        return clusters;
	    }
	    
	    private void mergeClusters(List<ShellcodeCluster> clusters) {
	        boolean mergeOccurred;
	        
	        do {
	            mergeOccurred = false;
	            
	             for (int i = 0; i < clusters.size(); i++) {
	                ShellcodeCluster clusterA = clusters.get(i);
	                
	                for (int j = i + 1; j < clusters.size(); j++) {
	                    ShellcodeCluster clusterB = clusters.get(j);
	                    
	                    Address endA = clusterA.getEndAddress();
	                    Address startB = clusterB.getStartAddress();
	                    
	                    if (endA != null && startB != null) {
	                        long distance;
	                        
	                        if (endA.compareTo(startB) > 0) {
	                            distance = 0;
	                        } else {
	                            distance = startB.subtract(endA);
	                        }
	                        
	                        if (distance <= EXTENDED_PROXIMITY_THRESHOLD) {
	                            clusterA.matches.addAll(clusterB.matches);
	                            clusterA.matches.sort((a, b) -> a.address.compareTo(b.address));
	                            clusters.remove(j);
	                            mergeOccurred = true;
	                            break;
	                        }
	                    }
	                }
	                
	                if (mergeOccurred) {
	                    break;
	                }
	            }
	        } while (mergeOccurred);
	    }
	    
	    private int calculateClusterConfidence(ShellcodeCluster cluster) {
	        int score = 0;
	        
	        Map<SignatureType, Integer> signatureCounts = new HashMap<>();
	        
	        for (ShellcodeMatch match : cluster.matches) {
	            signatureCounts.put(match.type, signatureCounts.getOrDefault(match.type, 0) + 1);
	        }
	        
	        score += signatureCounts.getOrDefault(SignatureType.CRITICAL, 0) * 50;
	        score += signatureCounts.getOrDefault(SignatureType.HIGH, 0) * 30;
	        score += signatureCounts.getOrDefault(SignatureType.MEDIUM, 0) * 15;
	        score += signatureCounts.getOrDefault(SignatureType.LOW, 0) * 5;
	        score += signatureCounts.getOrDefault(SignatureType.VERY_LOW, 0) * 2;
	        
	         if (cluster.matches.size() >= 3) {
	            Address start = cluster.getStartAddress();
	            Address end = cluster.getEndAddress();
	            
	            if (start != null && end != null) {
	                long size = end.subtract(start);
	                if (size > 0) {
	                    double density = cluster.matches.size() / (double)size;
	                    if (density > 0.1) { 
	                        score += 20;
	                    } else if (density > 0.05) {  
	                        score += 10;
	                    }
	                }
	            }
	        }
	        
	       if (signatureCounts.getOrDefault(SignatureType.CRITICAL, 0) > 0) {
	            score += 30;  
	        }
	        
	         int signatureTypeCount = signatureCounts.size();
	        score += signatureTypeCount * 5;
	        if (cluster.matches.size() > 20) {
	            score -= 10;  
	        }
	        
	        return score;
	    }
	    
	  
	    
	    private void markClusterAsShellcode(ShellcodeCluster cluster, int confidenceScore,  TaskMonitor monitor) {
	        if (cluster.matches.isEmpty()) {
	            return;
	        }
	        
	        String confidenceLevel;
	        if (confidenceScore >= CRITICAL_CONFIDENCE_SCORE) {
	            confidenceLevel = "CRITICAL";
	        } else if (confidenceScore >= HIGH_CONFIDENCE_SCORE) {
	            confidenceLevel = "HIGH";
	        } else if (confidenceScore >= MEDIUM_CONFIDENCE_SCORE) {
	            confidenceLevel = "MEDIUM";
	        } else {
	            confidenceLevel = "LOW";
	        }
	        
	        Address startAddress = cluster.getStartAddress();
	        Address endAddress = cluster.getEndAddress();
	        
	        if (startAddress == null || endAddress == null) {
	            return;
	        }
	        
	         long estimatedSize = endAddress.subtract(startAddress) + 10;
	        
	         StringBuilder description = new StringBuilder();
	        description.append("POTENTIAL SHELLCODE DETECTED\n");
	        description.append("Confidence: ").append(confidenceLevel).append(" (").append(confidenceScore).append(")\n");
	        description.append("Size: ~").append(estimatedSize).append(" bytes\n\n");
	        description.append("Detected signatures:\n");
	        
	        Map<String, Integer> signatureSummary = new HashMap<>();
	        for (ShellcodeMatch match : cluster.matches) {
	            signatureSummary.put(match.description, signatureSummary.getOrDefault(match.description, 0) + 1);
	        }
	        
	        for (Map.Entry<String, Integer> entry : signatureSummary.entrySet()) {
	            description.append("- ").append(entry.getKey());
	            if (entry.getValue() > 1) {
	                description.append(" (x").append(entry.getValue()).append(")");
	            }
	            description.append("\n");
	        }
	        
	        String category;
	        if (confidenceScore >= HIGH_CONFIDENCE_SCORE) {
	            category = "Shellcode [High Confidence]";
	        } else {
	            category = "Potential Shellcode";
	        }
	        
	        program.getBookmarkManager().setBookmark(
	            startAddress, 
	            category, 
	            "Score: " + confidenceScore, 
	            description.toString()
	        );
	        
	         program.getListing().setComment(
	            startAddress, 
	            CodeUnit.PRE_COMMENT, 
	            description.toString()
	        );
	        
	         if (confidenceScore >= HIGH_CONFIDENCE_SCORE) {
	        	    try {
	        	        AddressSet shellcodeRegion = new AddressSet(startAddress, endAddress);
	        	        program.getListing().clearCodeUnits(startAddress, endAddress, false);

	        	        Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
	        	        AddressSet disassembledAddresses = disassembler.disassemble(startAddress, shellcodeRegion);
	        	        boolean success = disassembledAddresses != null && !disassembledAddresses.isEmpty();

	        	        if (!success) {
	        	            Msg.error(this, "Disassembly failed at " + startAddress);
	        	        }

	        	        try {
	        	            program.getFunctionManager().createFunction(
	        	                "shellcode_" + startAddress,
	        	                startAddress,
	        	                shellcodeRegion,
	        	                SourceType.ANALYSIS
	        	            );
	        	        } catch (Exception e) {
	        	            Msg.debug(this, "Could not create function at " + startAddress + ": " + e.getMessage());
	        	        }
	        	    } catch (Exception e) {
	        	        Msg.error(this, "Error processing shellcode at " + startAddress + ": " + e.getMessage());
	        	    }
	        	}
	        
	        results.add(new ShellCodeOutput(confidenceScore, startAddress));
	        Msg.info(this, "Shellcode detected at " + startAddress + " (confidence: " + confidenceScore + ")");
	    }
	    
	    private static class ShellcodeSignature {
	        final byte[] pattern;
	        final String description;
	        final SignatureType type;
	        
	        ShellcodeSignature(byte[] pattern, String description, SignatureType type) {
	            this.pattern = pattern;
	            this.description = description;
	            this.type = type;
	        }
	    }
	    
	    private static class ShellcodeMatch {
	        final Address address;
	        final String description;
	        final SignatureType type;
	        
	        ShellcodeMatch(Address address, String description, SignatureType type) {
	            this.address = address;
	            this.description = description;
	            this.type = type;
	        }
	    }
	    
	    private static class ShellcodeCluster {
	        final List<ShellcodeMatch> matches;
	        
	        ShellcodeCluster(List<ShellcodeMatch> matches) {
	            this.matches = matches;
	        }
	        
	        Address getStartAddress() {
	            if (matches.isEmpty()) {
	                return null;
	            }
	            return matches.get(0).address;
	        }
	        
	        Address getEndAddress() {
	            if (matches.isEmpty()) {
	                return null;
	            }
	            return matches.get(matches.size() - 1).address;
	        }
	    }
}