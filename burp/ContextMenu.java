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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.table.DefaultTableModel;

@SuppressWarnings("serial")
public class ContextMenu extends JPopupMenu {
    DataStructure data;
    
    JMenuItem clearAll;
    JMenuItem intruder;
    JMenuItem repeater;
    JMenuItem scanner;

    public ContextMenu(IBurpExtenderCallbacks callbacks){
        this.clearAll = new JMenuItem("Clear all");
        this.clearAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {     
                clear();
            }
        });
        
        this.intruder = new JMenuItem("Send to Intruder");
        this.intruder.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] rowIndexes = data.getTable().getSelectedRows();

                // Highlighted rows
                for(int i = 0; i < rowIndexes.length; i++) {
                    HttpRequest httpRequest = data.getHttpRequests().get(rowIndexes[i]);

                    callbacks.sendToIntruder(httpRequest.getHost(), httpRequest.getPort(), httpRequest.getUseHttps(), httpRequest.getRequest());
                }
            }
        });

        this.repeater = new JMenuItem("Send to Repeater");
        this.repeater.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] rowIndexes = data.getTable().getSelectedRows();

                // Highlighted rows 
                for(int i = 0; i < rowIndexes.length; i++) {

                    HttpRequest httpRequest = data.getHttpRequests().get(rowIndexes[i]);
                    callbacks.sendToRepeater(httpRequest.getHost(), httpRequest.getPort(), httpRequest.getUseHttps(), 
                        httpRequest.getRequest(), (String) data.getTable().getValueAt(rowIndexes[i], 4));
                }
            }
        });

        this.scanner = new JMenuItem("Do an active scan");
        this.scanner.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] rowIndexes = data.getTable().getSelectedRows();

                // Highlighted rows
                for(int i = 0; i < rowIndexes.length; i++) {
                    HttpRequest httpRequest = data.getHttpRequests().get(rowIndexes[i]);

                    callbacks.doActiveScan(httpRequest.getHost(), httpRequest.getPort(), httpRequest.getUseHttps(), httpRequest.getRequest());
                }
            }
        });

        add(scanner);
        add(repeater);
        add(intruder);
        add(new JSeparator());
        add(clearAll);
    }

    public void setDataStructure(DataStructure data) {
        this.data = data;
    }

    private void clear() {
        data.setFileTextField("");
        data.setInfoLabel("Copyright \u00a9 2016 Alexandre Teyar All Rights Reserved");
        DefaultTableModel model = (DefaultTableModel) data.getTable().getModel();
        model.setRowCount(0);
        data.getHttpRequests().clear();
    }
}
