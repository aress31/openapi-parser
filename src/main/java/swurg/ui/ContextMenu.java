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
import com.google.common.primitives.Ints;
import java.util.Collections;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.table.DefaultTableModel;

@SuppressWarnings("serial")
class ContextMenu extends JPopupMenu {

  private List<HttpRequestResponse> httpRequestResponses;

  ContextMenu(
      IBurpExtenderCallbacks callbacks, Tab tab
  ) {
    JMenuItem addToSiteMap = new JMenuItem("Add to site map");
    addToSiteMap.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
        callbacks.addToSiteMap(httpRequestResponse);
      }
    });

    JMenuItem activeScan = new JMenuItem("Do an active scan");
    activeScan.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
        callbacks.doActiveScan(httpRequestResponse.getHttpService().getHost(),
            httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
            httpRequestResponse.getRequest()
        );
      }
    });

    JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
    sendToIntruder.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
        callbacks.sendToIntruder(httpRequestResponse.getHttpService().getHost(),
            httpRequestResponse.getHttpService().getPort(),
            httpRequestResponse.isUseHttps(), httpRequestResponse.getRequest()
        );
      }
    });

    JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
    sendToRepeater.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
        callbacks.sendToRepeater(httpRequestResponse.getHttpService().getHost(),
            httpRequestResponse.getHttpService().getPort(),
            httpRequestResponse.isUseHttps(), httpRequestResponse.getRequest(),
            String.format("%s %s%s", tab.getTable().getValueAt(index, 1),
                tab.getTable().getValueAt(index, 4), tab.getTable().getValueAt(index, 5))
        );
      }
    });

    JMenuItem sendToComparer = new JMenuItem("Send to Comparer");
    sendToComparer.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = this.httpRequestResponses.get(index);
        callbacks.sendToComparer(httpRequestResponse.getRequest());
      }
    });

    JMenuItem clear = new JMenuItem("Clear item(s)");
    clear.addActionListener(e -> {
      // we go through the indices in decreasing order so we do not need to worry about shifting them
      List<Integer> indexes = Ints.asList(tab.getTable().getSelectedRows());
      indexes.sort(Collections.reverseOrder());

      for (int index : indexes) {
        // set the entry to 'null' rather than removing them to avoid any potential issue with the list order
        this.httpRequestResponses.remove(index);
        ((DefaultTableModel) tab.getTable().getModel()).removeRow(index);
      }

      // updating the rows' index
      for (int row = 0; row < tab.getTable().getRowCount(); row++) {
        tab.getTable().getModel().setValueAt(Integer.toString(row), row, 0);
      }
    });

    JMenuItem clearAll = new JMenuItem("Clear all");
    clearAll.addActionListener(e -> {
      this.httpRequestResponses.clear();
      ((DefaultTableModel) tab.getTable().getModel()).setRowCount(0);
    });

    add(addToSiteMap);
    add(new JSeparator());
    add(activeScan);
    add(sendToIntruder);
    add(sendToRepeater);
    add(sendToComparer);
    add(new JSeparator());
    add(clear);
    add(clearAll);
  }

  void setHttpRequestResponses(List<HttpRequestResponse> httpRequestResponses) {
    this.httpRequestResponses = httpRequestResponses;
  }
}
