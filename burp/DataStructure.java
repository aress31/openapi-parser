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

import java.awt.Color;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.JTextField;

import java.util.List;

public class DataStructure {
	private List<HttpRequest> httpRequests;

	private JTable table;
	private JTextField fileTextField;
	private JLabel infoLabel;

	public DataStructure(JTable table, List<HttpRequest> httpRequests, JTextField fileTextField, JLabel infoLabel) {
		this.table = table;
		this.httpRequests = httpRequests;
		this.fileTextField = fileTextField;
		this.infoLabel = infoLabel;
	}

	public JTable getTable() {
		return this.table;
	}

	public List<HttpRequest> getHttpRequests() {
		return this.httpRequests;
	}

	public void setFileTextField(String text) {
		this.fileTextField.setText(text);
	}

	public void setInfoLabel(String text) {
		this.infoLabel.setForeground(Color.BLACK);
		this.infoLabel.setText(text);
	}
}
