package burp;

import static burp.BurpExtender.COPYRIGHT;
import static burp.BurpExtender.EXTENSION;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.swing.JMenuItem;
import javax.swing.table.DefaultTableModel;

import swurg.gui.ParserPanel;
import swurg.process.Loader;
import swurg.utilities.LogEntry;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

public class MyContextMenuItemsProvider implements ContextMenuItemsProvider {

  private MontoyaApi montoyaApi;
  private ParserPanel tab;
  private Logging logging;

  MyContextMenuItemsProvider(MontoyaApi montoyaApi, ParserPanel tab) {
    this.montoyaApi = montoyaApi;
    this.logging = montoyaApi.logging();
    this.tab = tab;
  }

  @Override
  public List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
    List<Component> jMenuItems = new ArrayList<>();
    JMenuItem sendToOpenAPIParser = new JMenuItem(String.format("Send to %s", EXTENSION));

    sendToOpenAPIParser.addActionListener(e -> {
      for (IHttpRequestResponse selectedMessage : contextMenuEvent.getSelectedMessages()) {
        IRequestInfo requestInfo = this.montoyaApi.getHelpers().analyzeRequest(selectedMessage);
        String resource = requestInfo.getUrl().toString();

        // TODO: Redundant piece of code and buggy need to set 'logEntries'
        try {
          // Loader loader = new Loader(montoyaApi);
          List<LogEntry> logEntries = loader.parseOpenAPI(loader.processOpenAPI(resource));

          this.tab.setResourceTextField(resource);

          // Updating table model
          for (LogEntry entry : logEntries) {
            ((DefaultTableModel) this.tab.getTable().getModel())
                .addRow(new Object[] { ((DefaultTableModel) this.tab.getTable().getModel()).getRowCount(),
                    entry.getHttpMethod(), entry.getServer(), entry.getParameters(), entry.getParameters(),
                    Optional.ofNullable(entry.getDescription()).orElse("N/A") });
          }

          this.tab.printStatus(COPYRIGHT,
              javax.swing.UIManager.getLookAndFeelDefaults().getColor("TextField.foreground"));
        } catch (Exception e1) {
          this.logging.logToOutput(String.format("%s -> %s", this.getClass().getName(), e1.getMessage()));
          this.tab.printStatus(e1.getMessage(),
              javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.burpError"));
        }
      }
    });

    jMenuItems.add(sendToOpenAPIParser);

    return jMenuItems;
  }
}
