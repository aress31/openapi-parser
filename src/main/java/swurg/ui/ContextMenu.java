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
import java.awt.Color;
import java.awt.event.ActionEvent;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.table.DefaultTableModel;

@SuppressWarnings("serial")
class ContextMenu extends JPopupMenu {

  private List<HttpRequestResponse> httpRequestResponses;
  private Tab tab;

  ContextMenu(
      IBurpExtenderCallbacks callbacks, Tab tab
  ) {
    this.tab = tab;

    JMenuItem add_to_site_map = new JMenuItem("Add to site map");
    add_to_site_map.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = httpRequestResponses.get(index);
        callbacks.addToSiteMap(httpRequestResponse);
      }
    });

    JMenuItem do_an_active_scan = new JMenuItem("Do an active scan");
    do_an_active_scan.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = httpRequestResponses.get(index);
        callbacks.doActiveScan(httpRequestResponse.getHttpService().getHost(),
            httpRequestResponse.getHttpService().getPort(), httpRequestResponse.isUseHttps(),
            httpRequestResponse.getRequest()
        );
      }
    });

    JMenuItem send_to_intruder = new JMenuItem("Send to Intruder");
    send_to_intruder.addActionListener((ActionEvent e) -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = httpRequestResponses.get(index);
        callbacks.sendToIntruder(httpRequestResponse.getHttpService().getHost(),
            httpRequestResponse.getHttpService().getPort(),
            httpRequestResponse.isUseHttps(), httpRequestResponse.getRequest()
        );
      }
    });

    JMenuItem send_to_repeater = new JMenuItem("Send to Repeater");
    send_to_repeater.addActionListener(e -> {
      for (int index : tab.getTable().getSelectedRows()) {
        HttpRequestResponse httpRequestResponse = httpRequestResponses.get(index);
        callbacks.sendToRepeater(httpRequestResponse.getHttpService().getHost(),
            httpRequestResponse.getHttpService().getPort(),
            httpRequestResponse.isUseHttps(), httpRequestResponse.getRequest(),
            (String) tab.getTable().getValueAt(index, 5)
        );
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

  public void setHttpRequestResponses(List<HttpRequestResponse> httpRequestResponses) {
    this.httpRequestResponses = httpRequestResponses;
  }

  private void clear() {
    ((DefaultTableModel) this.tab.getTable().getModel()).setRowCount(0);
    this.httpRequestResponses.clear();
    tab.displayStatus("Copyright \u00a9 2016 - 2018 Alexandre Teyar All Rights Reserved",
        Color.BLACK);
  }
}

