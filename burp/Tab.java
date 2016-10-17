<<<<<<< HEAD
/*
#    Copyright (C) 2016 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package burp;

import com.google.gson.Gson;
import com.google.gson.JsonElement;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import java.io.BufferedReader; 
import java.io.File; 
import java.io.FileReader; 
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;

import java.util.ArrayList;
import java.util.Map;
import java.util.List;

public class Tab implements ITab {
	private PrintWriter stderr;
	private Helper helper = new Helper();

	private ContextMenu contextMenu;
	private JLabel infoLabel;
	private JPanel container;
	private JTable table;
	private JTextField fileTextField;

	private int rowIndex = 1;

	private List<HttpRequest> httpRequests;

  	public Tab(IBurpExtenderCallbacks callbacks) {
  		stderr = new PrintWriter(callbacks.getStderr(), true);

 		httpRequests = new ArrayList<HttpRequest>();

  		contextMenu = new ContextMenu(callbacks);

  		// main container
  		container = new JPanel();
  		container.setLayout(new BorderLayout());
  		container.add(drawJFilePanel(), BorderLayout.NORTH);
  		container.add(drawJScrollTable());
  		container.add(drawJInfoPanel(), BorderLayout.SOUTH);
	}

	private JPanel drawJFilePanel() {
  		JPanel panel = new JPanel();
  		JLabel label = new JLabel("Parse from file:");
  		fileTextField = new JTextField("", 32);
  		JButton button = new JButton("Select File");

		fileTextField.setEditable(false);
  		button.addActionListener(new ButtonListener());

  		panel.add(label);
  		panel.add(fileTextField);
  		panel.add(button);

  		return panel;
	}

	class ButtonListener implements ActionListener {
		ButtonListener() {
			super();
		}

		public void actionPerformed (ActionEvent e) {
			if (e.getSource() instanceof JButton) {
				processFile();
			}
		}
	}

	private void processFile() {
		JFileChooser fileChooser = new JFileChooser();
	 	FileFilter filter = new FileNameExtensionFilter("Swagger Files (*.json)", "json");
		int result = fileChooser.showOpenDialog(container);

		fileChooser.addChoosableFileFilter(filter);
		fileChooser.setFileFilter(filter);

		if (result == JFileChooser.APPROVE_OPTION) {
		    File file = fileChooser.getSelectedFile();

		    //This is where a real application would open the file.
		    fileTextField.setText(file.getName());
			infoLabel.setForeground(Color.BLACK);
			infoLabel.setText(null);

		    try {
		    	Gson gson = new Gson();
		        BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
		        RESTful api = gson.fromJson(bufferedReader, RESTful.class);
		   		String infoText = "Title: " + api.getInfo().getTitle() + " | " +
		   			"Version: " + api.getInfo().getVersion()  + " | " +
		   			"Swagger: " + api.getSwagger();

				infoLabel.setForeground(Color.BLACK);
		   		infoLabel.setText(infoText);

		   		populateJTable(api);
		   	} catch (Exception ex) {
				StringWriter stringWriter = new StringWriter();
				ex.printStackTrace(new PrintWriter(stringWriter));
				stderr.println(stringWriter.toString());

				infoLabel.setForeground(Color.RED);
		   		infoLabel.setText("An error occured, please check the logs for further details");
		   	}
		} 
	}

	@SuppressWarnings("serial")
	private JScrollPane drawJScrollTable() {
		Object columns[] = {
			"#",
			"Host",
			"Method", 
			"Base Path",
			"Endpoint",
			"Params"
		};
		Object rows[][] = {};
        table = new JTable(new DefaultTableModel(rows, columns) {
		    @Override
		    public boolean isCellEditable(int rows, int columns) {
		       return false;
		    }
		});

        JScrollPane scrollPane = new JScrollPane(table);

        table.setSelectionForeground(Color.BLACK);
        table.addMouseListener(new MouseAdapter() {    		
        	@Override
			public void mouseReleased(MouseEvent e) { 
				int selectedRow = table.rowAtPoint(e.getPoint());

		        if (selectedRow >= 0 && selectedRow < table.getRowCount()) {
		        	if (!table.getSelectionModel().isSelectedIndex(selectedRow)) {
						table.setRowSelectionInterval(selectedRow, selectedRow);
		        	}
		        }

			    if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {  
		        	this.show(e);
		    	}
		    }

		    private void show(MouseEvent e) {
		    	DataStructure data = new DataStructure(
              		table, 
              		httpRequests,
              		fileTextField,
              		infoLabel
            	);
            
				contextMenu.setDataStructure(data);
				contextMenu.show(e.getComponent(), e.getX(), e.getY());
		    }
		});

		return scrollPane;
	}

	public void resizeColumnWidth(JTable table) {
	    final TableColumnModel columnModel = table.getColumnModel();

	    for (int column = 0; column < table.getColumnCount(); column++) {
	        int width = 16; // Min width

	        for (int row = 0; row < table.getRowCount(); row++) {
	            TableCellRenderer renderer = table.getCellRenderer(row, column);
	            Component comp = table.prepareRenderer(renderer, row, column);
	            width = Math.max(comp.getPreferredSize().width +1 , width);
	        }

	        if(width > 300) {
	            width = 300;
	        }

	        columnModel.getColumn(column).setPreferredWidth(width);
	    }
	}

	private void populateJTable(RESTful api) {
		DefaultTableModel model = (DefaultTableModel) table.getModel();
		Gson gson = new Gson();

		for (String protocol : api.getSchemes()) {
			String host = api.getHost();
			String basePath = api.getBasePath();

			for (Map.Entry<String, JsonElement> path: api.getPaths().entrySet()) {
				String endpoint = path.getKey();
				String url = basePath + endpoint;

				for (Map.Entry<String, JsonElement> entry: path.getValue().getAsJsonObject().entrySet()) {
					Path call = gson.fromJson(entry.getValue(), Path.class);
					String httpMethod = entry.getKey().toUpperCase();
					call.setType(httpMethod);

					model.addRow(new Object[] {
							rowIndex,
							httpMethod,	
							host, 
							basePath, 
							endpoint,
							helper.parseParams(call.getParameters())		
						}
					);

					resizeColumnWidth(table);

					helper.populateHttpRequests(httpRequests, httpMethod, url, host, protocol, call.getParameters(), 
						api.getDefinitions(), call.getConsumes(), call.getProduces());

					rowIndex++;
				}
			}
		}
	}

	private JPanel drawJInfoPanel() {
		JPanel panel = new JPanel();
  		infoLabel = new JLabel("Copyright 2016 Alexandre Teyar All Rights Reserved");

  		panel.add(infoLabel);

  		return panel;
	}

	@Override
	public Component getUiComponent() {
		return container;
	}

	@Override
	public String getTabCaption() {
		return "Swurg";
   	}
=======
/*
#    Copyright (C) 2016 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package burp;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import java.io.BufferedReader; 
import java.io.File; 
import java.io.FileReader; 
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;

import java.util.ArrayList;
import java.util.Map;
import java.util.List;

public class Tab implements ITab {
	private IBurpExtenderCallbacks callbacks;
	private PrintWriter stderr;

	private ContextMenu contextMenu;
	private JLabel infoLabel;
	private JPanel container;
	private JTable table;
	private JTextField fileTextField;

	private Gson gson;
	private int rowIndex = 1;

	// Something to use with the # in the table maybe...
	private List<HttpRequest> httpRequests;

  	public Tab(IBurpExtenderCallbacks callbacks) {
  		this.callbacks = callbacks;
  		stderr = new PrintWriter(callbacks.getStderr(), true);

 		httpRequests = new ArrayList<HttpRequest>();

  		contextMenu = new ContextMenu(callbacks);

  		// main container
  		container = new JPanel();
  		container.setLayout(new BorderLayout());
  		container.add(drawFilePanel(), BorderLayout.NORTH);
  		container.add(drawScrollTable());
  		container.add(drawInfoPanel(), BorderLayout.SOUTH);
	}

	private JPanel drawFilePanel() {
  		JPanel panel = new JPanel();
  		JLabel label = new JLabel("Parse from file:");
  		fileTextField = new JTextField("", 32);
  		JButton button = new JButton("Select File");

		fileTextField.setEditable(false);
  		button.addActionListener(new ButtonListener());

  		panel.add(label);
  		panel.add(fileTextField);
  		panel.add(button);

  		return panel;
	}

	private JScrollPane drawScrollTable() {
		Object columns[] = {
			"#",
			"Method",
			"Host", 
			"Base Path",
			"Endpoint"
		};
		Object rows[][] = {};
        table = new JTable(new DefaultTableModel(rows, columns));
        JScrollPane scrollPane = new JScrollPane(table);

        table.setSelectionForeground(Color.BLACK);
        table.addMouseListener(new MouseAdapter() {    		
        	@Override
			public void mouseReleased(MouseEvent e) { 
				int selectedRow = table.rowAtPoint(e.getPoint());

		        if (selectedRow >= 0 && selectedRow < table.getRowCount()) {
		        	if (!table.getSelectionModel().isSelectedIndex(selectedRow)) {
						table.setRowSelectionInterval(selectedRow, selectedRow);
		        	}
		        }

			    if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {  
		        	this.show(e);
		    	}
		    }

		    private void show(MouseEvent e){
		    	int selectedRow = table.rowAtPoint(e.getPoint());
            	int selectedColumn = table.columnAtPoint(e.getPoint());

            	DataStructure data = new DataStructure(
              		table, 
              		httpRequests,
              		fileTextField,
              		infoLabel
            	);
            
				contextMenu.setDataStructure(data);
				contextMenu.show(e.getComponent(), e.getX(), e.getY());
		    }
		});

		return scrollPane;
	}

	private JPanel drawInfoPanel() {
		JPanel panel = new JPanel();
  		infoLabel = new JLabel("Copyright 2016 Alexandre Teyar All Rights Reserved");

  		panel.add(infoLabel);

  		return panel;
	}

	class ButtonListener implements ActionListener {
		ButtonListener() {
			super();
		}

		public void actionPerformed (ActionEvent e) {
			if (e.getSource() instanceof JButton) {
				parseFile();
			}
		}
	}

	private void parseFile() {
		JFileChooser fileChooser = new JFileChooser();
	 	FileFilter filter = new FileNameExtensionFilter("Swagger Files (*.json)", "json");
		int result = fileChooser.showOpenDialog(container);

		fileChooser.addChoosableFileFilter(filter);
		fileChooser.setFileFilter(filter);

		if (result == JFileChooser.APPROVE_OPTION) {
		    File file = fileChooser.getSelectedFile();

		    //This is where a real application would open the file.
		    fileTextField.setText(file.getName());
			infoLabel.setForeground(Color.BLACK);
			infoLabel.setText(null);

		    try {
		    	gson = new Gson();
		        BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
		        RESTful api = gson.fromJson(bufferedReader, RESTful.class);
		   		String infoText = "Title: " + api.getInfo().getTitle() + " | " +
		   			"Version: " + api.getInfo().getVersion()  + " | " +
		   			"Swagger: " + api.getSwagger();

				infoLabel.setForeground(Color.BLACK);
		   		infoLabel.setText(infoText);

		   		populateTable(api);
		   	} catch (Exception ex) {
				StringWriter stringWriter = new StringWriter();
				ex.printStackTrace(new PrintWriter(stringWriter));
				stderr.println(stringWriter.toString());

				infoLabel.setForeground(Color.RED);
		   		infoLabel.setText("An error occured, please check the logs for further details");
		   	}
		} 
	}

	private void populateTable(RESTful api) {
		DefaultTableModel model = (DefaultTableModel) table.getModel();

		for (String protocol : api.getSchemes()) {
			String host = api.getHost();
			String basePath = api.getBasePath();

			for (Map.Entry<String, JsonElement> path: api.getPaths().entrySet()) {
				String endpoint = path.getKey();
				String url = basePath + endpoint;

				for (Map.Entry<String, JsonElement> entry: path.getValue().getAsJsonObject().entrySet()) {
					Call call = gson.fromJson(entry.getValue(), Call.class);
					String httpMethod = entry.getKey().toUpperCase();
					String inQueryParams = "";
					String inBodyParams = "";

					call.setType(httpMethod);

					model.addRow(new Object[] {
							rowIndex,
							httpMethod,	
							host, 
							basePath, 
							endpoint			
						}
					);

					populateHttpRequests(httpMethod, url, host, protocol, call.getParameters(), 
						api.getDefinitions(), call.getConsumes(), call.getProduces());

					rowIndex++;
				}
			}
		}
	}

	private List<Object> protocolToPort(String protocol) {
		List<Object> result = new ArrayList<Object>();

		switch (protocol) {
			case "http": {
				result.add(80);
				result.add(false);
				return result;
			}

			case "https": {
				result.add(443);
				result.add(true);
				return result;
			}

			default: {
				infoLabel.setForeground(Color.RED);
				infoLabel.setText("Transport protocol not implemented");
				return null;
			}
		}
	}

	private String parseInPathParams(List<Parameter> params) {
		String result = "";

		if (params != null) {
			result = "?";

			for (Parameter param : params) {
				if (param.getIn().equals("path"))
				result += param.getName() + "={" + param.getType() + "}&";
			}

			result = result.substring(0, result.length() - 1);
		}

		return result;
	}

	private String parseInQueryParams(List<Parameter> params) {
		String result = "";

		if (params != null) {
			result = "?";

			for (Parameter param : params) {
				if (param.getIn().equals("query"))
				result += param.getName() + "={" + param.getType() + "}&";
			}

			result = result.substring(0, result.length() - 1);
		}

		return result;
	}

	private String parseInBodyParams(List<Parameter> params, JsonObject definitions) {
		String result = "";
		
		if (params != null) {
			for (Parameter param : params) {
				if (param.getIn().equals("body")) {
					result += parseSchemaParams(param.getName(), definitions);
				}
			}

			result = result.substring(0, result.length() - 1);
		}

		return result;
	}

	// Really messy but does the job - needs improvements!
	private String parseSchemaParams(String param, JsonObject definitions) {
		String result = "";

		for (Map.Entry<String, JsonElement> entry: definitions.entrySet()) {
			if (entry.getKey().equals(param)) {
				Schema schema = gson.fromJson(entry.getValue(), Schema.class);

				if (schema.getProperties() != null) {
					for (Map.Entry<String, JsonElement> entry1: schema.getProperties().entrySet()) {
						for (Map.Entry<String, JsonElement> entry2: entry1.getValue().getAsJsonObject().entrySet()) {
							if (entry2.getKey().equals("type")) {
								result += entry1.getKey() + "={" + entry2.getValue().getAsString() + "}&";
							} else if (entry2.getKey().equals("$ref")) {
								String[] parts = entry2.getValue().getAsString().split("/");
								stderr.println(parts[parts.length - 1]);
								result += parseSchemaParams(parts[parts.length - 1], definitions);
							}
						}
					}
				}
			}
		}

		return result;
	}

	private void populateHttpRequests(String httpMethod, String url, String host, String protocol, List<Parameter> params,	
		JsonObject definitions, List<String> consumes, List<String> produces) {
		switch (httpMethod) {
			case "GET": {
				String request = "GET " + url + parseInQueryParams(params) + " HTTP/1.1" + "\n" 
					+ "Host: " + host + "\n" 
					+ "Accept: " + String.join(",", produces);
				HttpRequest httpRequest = new HttpRequest(host, (Integer) protocolToPort(protocol).get(0), 
					(Boolean) protocolToPort(protocol).get(1), request.getBytes());

				httpRequests.add(httpRequest);
				break;
			}

			case "POST": {
				String request = "POST " + url + " HTTP/1.1" + "\n"
					+ "Host: " + host + "\n" 
					+ "Accept: " + String.join(",", produces) + "\n"
					+ "Content-Type: " + String.join(",", consumes)
					+ "\n\n"
					+ parseInBodyParams(params, definitions);
				HttpRequest httpRequest = new HttpRequest(host, (Integer) protocolToPort(protocol).get(0), 
					(Boolean) protocolToPort(protocol).get(1), request.getBytes());

				httpRequests.add(httpRequest);
				break;
			}

			case "DELETE": {
				String request = "DELETE " + url + parseInQueryParams(params) + " HTTP/1.1" + "\n"
					+ "Host: " + host + "\n"
					+ "Accept: " + String.join(",", produces);
				HttpRequest httpRequest = new HttpRequest(host, (Integer) protocolToPort(protocol).get(0), 
					(Boolean) protocolToPort(protocol).get(1), request.getBytes());

				httpRequests.add(httpRequest);
				break;
			}

			default: {
				infoLabel.setForeground(Color.RED);
				infoLabel.setText("HTTP method not implemented");
				break;
			}
		}
	}

	@Override
	public Component getUiComponent() {
		return container;
	}

	@Override
	public String getTabCaption() {
		return "Swurg";
   	}
>>>>>>> origin/master
}