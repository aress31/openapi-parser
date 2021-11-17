/*
#    Copyright (C) 2016-2021 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. F
*/

package swurg.gui;

import static burp.BurpExtender.COPYRIGHT;

import java.awt.BorderLayout;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;

public class ParametersPanel extends JPanel implements IHttpListener {

    private IBurpExtenderCallbacks callbacks;

    private JLabel statusLabel = new JLabel(COPYRIGHT);

    public ParametersPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        initComponents();
    }

    private void initComponents() {
        this.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setBorder(BorderFactory.createTitledBorder("Override Test Values"));

        JPanel southPanel = new JPanel();
        southPanel.add(this.statusLabel);

        this.add(mainPanel);
        this.add(southPanel, BorderLayout.SOUTH);
    }

    public void initParametersList() {
        // for (IHttpRequestResponse httpRequestResponse : this.httpRequestResponses) {
        // IRequestInfo requestInfo =
        // this.callbacks.getHelpers().analyzeRequest(httpRequestResponse.getRequest());
        // callbacks.printOutput(String.format(" -> %s", requestInfo.getParameters()));
        // }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // TODO Auto-generated method stub
    }
}
