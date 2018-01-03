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

package swurg.utils;

import swurg.model.HttpRequest;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class DataStructure {
    private JTable jTable;
    private JTextField jTextField;
    private JLabel jLabel;

    private List<HttpRequest> httpRequests;

    public DataStructure(JTable jTable, List<HttpRequest> httpRequests, JTextField jTextField, JLabel jLabel) {
        this.jTable = jTable;
        this.httpRequests = httpRequests;
        this.jTextField = jTextField;
        this.jLabel = jLabel;
    }

    public JTable getTable() {
        return this.jTable;
    }

    public List<HttpRequest> getHttpRequests() {
        return this.httpRequests;
    }

    public void setJTextFieldFile(String text) {
        this.jTextField.setText(text);
    }

    public void setJLabelInfo(String text) {
        this.jLabel.setForeground(Color.BLACK);
        this.jLabel.setText(text);
    }
}
