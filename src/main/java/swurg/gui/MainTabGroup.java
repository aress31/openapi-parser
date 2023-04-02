package swurg.gui;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTabbedPane;
import javax.swing.event.SwingPropertyChangeSupport;

import burp.api.montoya.MontoyaApi;
import swurg.utilities.LogEntry;

public class MainTabGroup extends JTabbedPane {

    private transient MontoyaApi montoyaApi;

    private ParserPanel parserPanel;
    // private ParametersPanel parametersPanel;
    private AboutPanel aboutPanel;

    public MainTabGroup(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        initComponents();
    }

    public ParserPanel getParserPanel() {
        return this.parserPanel;
    }

    // public ParametersPanel getParametersPanel() {
    // return this.parametersPanel;
    // }

    private void initComponents() {
        parserPanel = new ParserPanel(montoyaApi);
        // parametersPanel = new ParameterPanel(montoyaApi);
        aboutPanel = new AboutPanel();

        Model model = new Model();

        parserPanel.setModel(model);

        addTab("Parser", parserPanel);
        addTab("About", aboutPanel);

        model.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (!model.getLogEntries().isEmpty()) {
                    // addTab("Parameters", parametersPanel);
                }
            }
        });
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
        List<LogEntry> oldValue = this.logEntries;
        this.logEntries = logEntries;
        swingPropertyChangeSupport.firePropertyChange("logEntries", oldValue, logEntries);
    }
}
