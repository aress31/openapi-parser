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
#    limitations under the License. 
*/

package swurg.gui;

import static burp.BurpExtender.EXTENSION;

import java.awt.Component;

import javax.swing.JTabbedPane;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

public class MainTabGroup extends JTabbedPane implements ITab {

    private final IBurpExtenderCallbacks callbacks;

    private ParserPanel parserPanel;
    private ParametersPanel parametersPanel;

    public MainTabGroup(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        initComponents();
    }

    public ParserPanel getParserPanel() {
        return this.parserPanel;
    }

    private void initComponents() {
        this.parserPanel = new ParserPanel(callbacks);
        this.parametersPanel = new ParametersPanel(callbacks);

        this.addTab("Parser", parserPanel);
        this.addTab("Headers/Parameters", parametersPanel);
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    @Override
    public String getTabCaption() {
        return EXTENSION;
    }
}
