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

package swurg.ui;

import burp.IBurpExtenderCallbacks;
import swurg.model.HttpRequest;
import swurg.utils.DataStructure;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.event.ActionEvent;

@SuppressWarnings("serial")
public class ContextMenu extends JPopupMenu {
    private DataStructure dataStructure;

    ContextMenu(IBurpExtenderCallbacks callbacks) {
        JMenuItem scanner = new JMenuItem("Do an active scan");
        scanner.addActionListener(e -> {
            int[] rowIndexes = dataStructure.getTable().getSelectedRows();

            for (int rowIndex : rowIndexes) {
                HttpRequest httpRequest = dataStructure.getHttpRequests().get(rowIndex);

                callbacks.doActiveScan(
                        httpRequest.getHost(),
                        httpRequest.getPort(),
                        httpRequest.getUseHttps(),
                        httpRequest.getRequest()
                );
            }
        });

        JMenuItem intruder = new JMenuItem("Send to Intruder");
        intruder.addActionListener((ActionEvent e) -> {
            int[] rowIndexes = dataStructure.getTable().getSelectedRows();

            for (int rowIndex : rowIndexes) {
                HttpRequest httpRequest = dataStructure.getHttpRequests().get(rowIndex);

                callbacks.sendToIntruder(
                        httpRequest.getHost(),
                        httpRequest.getPort(),
                        httpRequest.getUseHttps(),
                        httpRequest.getRequest()
                );
            }
        });

        JMenuItem repeater = new JMenuItem("Send to Repeater");
        repeater.addActionListener(e -> {
            int[] rowIndexes = dataStructure.getTable().getSelectedRows();

            for (int rowIndex : rowIndexes) {

                HttpRequest httpRequest = dataStructure.getHttpRequests().get(rowIndex);
                callbacks.sendToRepeater(
                        httpRequest.getHost(),
                        httpRequest.getPort(),
                        httpRequest.getUseHttps(),
                        httpRequest.getRequest(),
                        (String) dataStructure.getTable().getValueAt(rowIndex, 5)
                );
            }
        });

        JMenuItem clearAll = new JMenuItem("Clear all");
        clearAll.addActionListener(e -> clear());

        add(scanner);
        add(intruder);
        add(repeater);
        add(new JSeparator());
        add(clearAll);
    }

    public void setDataStructure(DataStructure data) {
        this.dataStructure = data;
    }

    private void clear() {
        dataStructure.setJTextFieldFile(null);
        dataStructure.setJLabelInfo("Copyright \u00a9 2016 - 2018 Alexandre Teyar All Rights Reserved");
        DefaultTableModel model = (DefaultTableModel) dataStructure.getTable().getModel();
        model.setRowCount(0);
        dataStructure.getHttpRequests().clear();
    }
}

