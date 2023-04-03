package burp;

import static burp.MyBurpExtension.COPYRIGHT;
import static burp.MyBurpExtension.EXTENSION;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.UIManager;

import swurg.gui.ParserPanel;
import swurg.process.Loader;
import swurg.utilities.RequestWithMetadata;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

public class MyContextMenuItemsProvider implements ContextMenuItemsProvider {

  private MontoyaApi montoyaApi;
  private ParserPanel parserPanel;
  private Logging logging;

  MyContextMenuItemsProvider(MontoyaApi montoyaApi, ParserPanel parserPanel) {
    this.montoyaApi = montoyaApi;
    this.logging = montoyaApi.logging();
    this.parserPanel = parserPanel;
  }

  @Override
  public List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
    List<Component> menuItems = new ArrayList<>();
    JMenuItem openApiMenuItem = new JMenuItem(String.format("Send to %s", EXTENSION));

    openApiMenuItem.addActionListener(e -> {
      List<HttpRequestResponse> selectedHttpRequestResponses = contextMenuEvent.selectedRequestResponses();
      Loader loader = new Loader(montoyaApi);

      for (HttpRequestResponse selectedMessage : selectedHttpRequestResponses) {
        try {
          HttpRequest selectedRequest = selectedMessage.request();
          String url = selectedRequest.url();

          parserPanel.setResourceTextField(url);

          List<RequestWithMetadata> requestWithMetadatas = loader.parseOpenAPI(loader.processOpenAPI(url));

          // Update table dataModel
          // Bug parameters are swapped on the table with description and impossible to
          // left click on the table
          DefaultTableModel tableModel = (DefaultTableModel) parserPanel.getTable().getModel();

          for (int i = 0; i < tableModel.getColumnCount(); i++) {
            logging.logToOutput(tableModel.getColumnName(i));
          }

          SwingUtilities.invokeLater(() -> {
            for (RequestWithMetadata entry : requestWithMetadatas) {
              tableModel.addRow(new Object[] { tableModel.getRowCount(), entry.getHttpRequest().method(),
                  entry.getHttpRequest().httpService().host(), entry.getHttpRequest().path(), entry.getParameters(),
                  entry.getDescription() != null ? entry.getDescription() : "N/A" });
            }
          });

          parserPanel.printStatus(COPYRIGHT, UIManager.getColor("TextField.foreground"));
        } catch (Exception exception) {
          String errorMessage = String.format("Failed to process request %s: %s", selectedMessage.request().url(),
              exception.getMessage());
          logging.logToOutput(String.format("%s -> %s", this.getClass().getName(), errorMessage));
          parserPanel.printStatus(errorMessage, UIManager.getColor("BurpPalette.red1"));
        }
      }
    });

    menuItems.add(openApiMenuItem);

    return menuItems;
  }
}
