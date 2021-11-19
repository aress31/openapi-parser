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
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.swing.JTabbedPane;
import javax.swing.event.SwingPropertyChangeSupport;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import swurg.utilities.LogEntry;

public class MainTabGroup extends JTabbedPane implements ITab {

    private transient IBurpExtenderCallbacks callbacks;

    private ParametersPanel parametersPanel;
    private ParserPanel parserPanel;

    public MainTabGroup(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        initComponents();
    }

    public ParametersPanel getParametersPanel() {
        return this.parametersPanel;
    }

    public ParserPanel getParserPanel() {
        return this.parserPanel;
    }

    private void initComponents() {
        this.parserPanel = new ParserPanel(callbacks);
        this.parametersPanel = new ParametersPanel(callbacks);
        AboutPanel aboutPanel = new AboutPanel();

        Model model = new Model();

        this.parserPanel.setModel(model);
        parametersPanel.setModel(model);

        this.addTab("Parser", parserPanel);

        model.addPropertyChangeListener(new PropertyChangeListener() {
            // Reorder the tabs whenever ParameterPanel is mounted
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (!model.getLogEntries().isEmpty()) {
                    removeTabAt(1);
                    addTab("Parameters", parametersPanel);
                    addTab("About", aboutPanel);
                } else {
                    removeTabAt(1);
                }
            }
        });

        this.addTab("About", aboutPanel);
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

class Model {

    private List<LogEntry> logEntries = new ArrayList<>();
    private SwingPropertyChangeSupport swingPropertyChangeSupport = new SwingPropertyChangeSupport(this);

    public void addPropertyChangeListener(PropertyChangeListener propertyChangeListener) {
        swingPropertyChangeSupport.addPropertyChangeListener(propertyChangeListener);
    }

    public void removePropertyChangeListener(PropertyChangeListener propertyChangeListener) {
        swingPropertyChangeSupport.removePropertyChangeListener(propertyChangeListener);
    }

    public List<LogEntry> getLogEntries() {
        return this.logEntries;
    }

    public void setLogEntries(List<LogEntry> logEntries) {
        this.logEntries = logEntries;
        swingPropertyChangeSupport.firePropertyChange("logEntries", UUID.randomUUID().toString(),
                UUID.randomUUID().toString());
    }
}
