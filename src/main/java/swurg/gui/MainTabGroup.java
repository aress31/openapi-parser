package swurg.gui;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTabbedPane;

import burp.api.montoya.MontoyaApi;
import burp.http.MyHttpRequest;
import swurg.gui.views.AboutPanel;
import swurg.gui.views.ParametersPanel;
import swurg.gui.views.ParserPanel;
import swurg.observers.MyObserver;

import lombok.Data;

@Data
public class MainTabGroup extends JTabbedPane implements MyObserver {

    private final MontoyaApi montoyaApi;

    private final List<MyHttpRequest> myHttpRequests;

    private ParserPanel parserPanel;
    private ParametersPanel parametersPanel;
    private AboutPanel aboutPanel;

    public MainTabGroup(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.myHttpRequests = new ArrayList<>();

        initComponents();

        this.parserPanel.getParserTableModel().registerObserver(this);
        this.parserPanel.getParserTableModel().registerObserver(this.parametersPanel);
    }

    private void initComponents() {
        parserPanel = new ParserPanel(this.montoyaApi, this.myHttpRequests);
        aboutPanel = new AboutPanel(this.montoyaApi);
        parametersPanel = new ParametersPanel(this.montoyaApi, this.myHttpRequests);

        addTab("Parser", parserPanel);
        addTab("About", aboutPanel);
    }

    @Override
    public void onMyHttpRequestsUpdate() {
        if (indexOfComponent(this.parametersPanel) == -1 && !this.myHttpRequests.isEmpty()) {
            removeTabAt(indexOfComponent(this.aboutPanel));
            addTab("Parameters", this.parametersPanel);
            addTab("About", this.aboutPanel);
        } else if (indexOfComponent(this.parametersPanel) != -1 && this.myHttpRequests.isEmpty())
            removeTabAt(indexOfComponent(this.parametersPanel));
    }
}