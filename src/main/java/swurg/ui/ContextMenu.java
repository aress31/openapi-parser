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

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;

@SuppressWarnings("serial")
class ContextMenu extends JPopupMenu {
    private IBurpExtenderCallbacks callbacks;
    private List<HttpRequestResponse> httpRequestResponses;
    private Tab tab;

    ContextMenu(IBurpExtenderCallbacks callbacks, List<HttpRequestResponse> httpRequestResponses, Tab tab) {
        this.callbacks = callbacks;
        this.httpRequestResponses = httpRequestResponses;
        this.tab = tab;

        JMenuItem add_to_site_map = new JMenuItem("Add to site map");
        add_to_site_map.addActionListener(e -> {
            int[] rowIndexes = this.tab.getTable().getSelectedRows();

            for (int rowIndex : rowIndexes) {
                HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(rowIndex);
                this.callbacks.addToSiteMap(httpRequestResponse);
            }
        });

        JMenuItem do_an_active_scan = new JMenuItem("Do an active scan");
        do_an_active_scan.addActionListener(e -> {
            int[] rowIndexes = tab.getTable().getSelectedRows();

            for (int rowIndex : rowIndexes) {
                HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(rowIndex);

                this.callbacks.doActiveScan(httpRequestResponse.getHttpService().getHost(), httpRequestResponse
                        .getHttpService().getPort(), httpRequestResponse.isUseHttps(), httpRequestResponse.getRequest
                        ());
            }
        });

        JMenuItem send_to_intruder = new JMenuItem("Send to Intruder");
        send_to_intruder.addActionListener((ActionEvent e) -> {
            int[] rowIndexes = this.tab.getTable().getSelectedRows();

            for (int rowIndex : rowIndexes) {
                HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(rowIndex);

                this.callbacks.sendToIntruder(httpRequestResponse.getHttpService().getHost(), httpRequestResponse
                        .getHttpService().getPort(), httpRequestResponse.isUseHttps(), httpRequestResponse.getRequest
                        ());
            }
        });

        JMenuItem send_to_repeater = new JMenuItem("Send to Repeater");
        send_to_repeater.addActionListener(e -> {
            int[] rowIndexes = this.tab.getTable().getSelectedRows();

            for (int rowIndex : rowIndexes) {

                HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(rowIndex);
                this.callbacks.sendToRepeater(httpRequestResponse.getHttpService().getHost(), httpRequestResponse
                        .getHttpService().getPort(), httpRequestResponse.isUseHttps(), httpRequestResponse.getRequest
                        (), (String) this.tab.getTable().getValueAt(rowIndex, 5));
            }
        });

        JMenuItem clearAll = new JMenuItem("Clear all");
        clearAll.addActionListener(e -> clear());

        add(add_to_site_map);
        add(do_an_active_scan);
        add(send_to_intruder);
        add(send_to_repeater);
        add(new JSeparator());
        add(clearAll);
    }

    private void clear() {
        DefaultTableModel defaultTableModel = (DefaultTableModel) this.tab.getTable().getModel();
        defaultTableModel.setRowCount(0);
        this.httpRequestResponses.clear();
        tab.displayStatus("Copyright \u00a9 2016 - 2018 Alexandre Teyar All Rights Reserved", Color.BLACK);
    }
}

