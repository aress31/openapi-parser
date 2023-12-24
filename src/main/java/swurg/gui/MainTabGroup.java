package swurg.gui;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTabbedPane;

import burp.api.montoya.MontoyaApi;
import burp.http.MyHttpRequest;
import swurg.gui.views.AboutPanel;
import swurg.gui.views.ParametersPanel;
import swurg.gui.views.ParserPanel;
import swurg.observers.ParserTableModelObserver;

import lombok.Data;

@Data
public class MainTabGroup extends JTabbedPane implements ParserTableModelObserver {

    private final transient MontoyaApi montoyaApi;

    private ParserPanel parserPanel;
    private ParametersPanel parametersPanel;
    private AboutPanel aboutPanel;

    List<MyHttpRequest> myHttpRequests;

    public MainTabGroup(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.myHttpRequests = new ArrayList<>();

        initComponents();

        parserPanel.getParserTableModel().registerObserver(this);
        parserPanel.getParserTableModel().registerParametersPanelObserver(parametersPanel);

    }

    private void initComponents() {
        parserPanel = new ParserPanel(montoyaApi, myHttpRequests);
        aboutPanel = new AboutPanel();
        parametersPanel = new ParametersPanel(montoyaApi, myHttpRequests);

        addTab("Parser", parserPanel);
        addTab("About", aboutPanel);
    }

    @Override
    public void onRequestWithMetadatasUpdate() {
        if (indexOfComponent(parametersPanel) == -1 && !myHttpRequests.isEmpty()) {
            removeTabAt(indexOfComponent(aboutPanel));
            addTab("Parameters", parametersPanel);
            addTab("About", aboutPanel);
        } else if (indexOfComponent(parametersPanel) != -1 && myHttpRequests.isEmpty())
            removeTabAt(indexOfComponent(parametersPanel));

    }
}