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

import java.awt.BorderLayout;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import resources.Icons;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class CodeInjectionPlugin extends ProgramPlugin {

	MyProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CodeInjectionPlugin(PluginTool tool) {
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName, this.getCurrentProgram());

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// Acquire services if necessary
	}

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;
		
		private Program currentProgram;
		
		public MyProvider(Plugin plugin, String owner, Program program) {
			super(plugin.getTool(), "Skeleton Provider", owner);
			this.currentProgram = program;
			
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			
			JButton scanButton = new JButton("Scan");
	        scanButton.addActionListener(e -> {
				try {
					runAnalysis();
				} catch (CancelledException e1) {
					// TODO Auto-generated catch block
					Msg.debug(this, e1.getMessage());
				}
			});
	        panel.add(scanButton, BorderLayout.SOUTH);
	        
			setVisible(true);
		}
		
		private void runAnalysis() throws CancelledException {
	        if (currentProgram != null) {
	            new CodeInjectionAnalyzer().added(currentProgram, null, null, null);
	        }
	    }

		// Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
