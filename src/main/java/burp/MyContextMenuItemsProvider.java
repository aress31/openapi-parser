package burp;

import static burp.MyBurpExtension.COPYRIGHT;
import static burp.MyBurpExtension.EXTENSION;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import swurg.gui.components.tables.models.ParserTableModel;
import swurg.gui.views.ParserPanel;
import swurg.workers.Worker;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.http.MyHttpRequest;

public class MyContextMenuItemsProvider implements ContextMenuItemsProvider {
  private final ParserPanel parserPanel;
  private final Logging logging;

  public MyContextMenuItemsProvider(MontoyaApi montoyaApi, ParserPanel parserPanel) {
    this.logging = montoyaApi.logging();

    this.parserPanel = parserPanel;
  }

  @Override
  public List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
    List<Component> menuItems = new ArrayList<>();

    JMenuItem openApiMenuItem = new JMenuItem(String.format("Send to %s", EXTENSION));
    openApiMenuItem.addActionListener(e -> {
      try {
        List<HttpRequestResponse> selectedHttpRequestResponses = contextMenuEvent.selectedRequestResponses();
        Worker worker = new Worker();

        selectedHttpRequestResponses.forEach(selectedMessage -> {
          HttpRequest selectedRequest = selectedMessage.request();
          String url = selectedRequest.url();

          ParserTableModel parserTableModel = (ParserTableModel) this.parserPanel.getTable().getModel();
          List<MyHttpRequest> parsedMyHttpRequests = worker.parseOpenAPI(worker.processOpenAPI(url));

          SwingUtilities.invokeLater(() -> {
            parserTableModel.addRows(parsedMyHttpRequests);
            parserPanel.getResourceTextField().setText(url);
            parserPanel.getStatusPanel().updateStatus(COPYRIGHT, UIManager.getColor("TextField.foreground"));
          });
        });
      } catch (Exception exception) {
        logging.raiseErrorEvent(exception.getMessage());

        String message = String.format(
            "Failed to process request %s. Check the extension's error log for the stack trace and report the issue.",
            ((HttpRequestResponse) contextMenuEvent.selectedRequestResponses().get(0)).request().url());
        SwingUtilities.invokeLater(() -> {
          parserPanel.getStatusPanel().updateStatus(message, UIManager.getColor("BurpPalette.red1"));
        });
      }
    });

    menuItems.add(openApiMenuItem);

    return menuItems;
  }
}
