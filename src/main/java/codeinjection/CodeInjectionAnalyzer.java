/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package codeinjection;

import javax.swing.JOptionPane;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class CodeInjectionAnalyzer extends AbstractAnalyzer {

	public CodeInjectionAnalyzer() {

		// Name the analyzer and give it a description.

		super("Shell Code Injection Analyzer",
				"This Plugin is used to detect possible injection attacks for x86 systems", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it. Return
		// true
		// if it can.

		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		ShellCodeDetector shellcodeDetector = new ShellCodeDetector(program);
		shellcodeDetector.analyze(monitor);

		String outputString = "";
		for (ShellCodeOutput result : shellcodeDetector.results) {
			outputString += result.toString() + "\n";
		}

		if (!shellcodeDetector.results.isEmpty()) {
			APIScanner scanner = new APIScanner(program);
			scanner.scan(monitor);
			
			outputString += "=============== \n";
			for (APIScannerResults result : scanner.results) {
				outputString += result.toString() + "\n";
			}
		}

		OutputStringWrapper output = new OutputStringWrapper(outputString);

		javax.swing.SwingUtilities.invokeLater(() -> {
			JOptionPane.showMessageDialog(null, output.toString(), "Analysis Results", JOptionPane.INFORMATION_MESSAGE);
		});

		return true;
	}
}
