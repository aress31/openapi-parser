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
		        REST api = gson.fromJson(bufferedReader, REST.class);
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

	private void populateTable(REST api) {
		DefaultTableModel model = (DefaultTableModel) table.getModel();

		for (String protocol : api.getSchemes()) {
			String host = api.getHost();
			String basePath = api.getBasePath();

			for (Map.Entry<String,JsonElement> path: api.getPaths().entrySet()) {
				String endpoint = path.getKey();
				String url = basePath + endpoint;

				for (Map.Entry<String,JsonElement> entry: path.getValue().getAsJsonObject().entrySet()) {
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

					populateHttpRequests(httpMethod, url, host, protocol, call.getParameters(), call.getConsumes(), call.getProduces());

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

	private String parseInQueryParams(List<Call.Parameter> params) {
		String result = "";

		if (params != null) {
			result = "?";

			for (Call.Parameter param : params) {
				if (param.getIn().equals("query"))
				result += param.getName() + "={" + param.getType() + "}&";
			}

			result = result.substring(0, result.length() - 1);
		}

		return result;
	}

	private String parseInBodyParams(List<Call.Parameter> params) {
		String result = "";

		return result;
	}

	private void populateHttpRequests(String httpMethod, String url, String host, String protocol, List<Call.Parameter> params,
			List<String> consumes, List<String> produces) {
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
					+ parseInBodyParams(params);
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
}