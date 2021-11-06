package burp;

import static burp.BurpExtender.COPYRIGHT;
import static burp.BurpExtender.EXTENSION;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import io.swagger.v3.oas.models.OpenAPI;
import swurg.process.Loader;
import swurg.ui.Tab;

public class ContextMenuFactory implements IContextMenuFactory {

  private IBurpExtenderCallbacks callbacks;
  private Tab tab;

  ContextMenuFactory(IBurpExtenderCallbacks callbacks, Tab tab) {
    this.callbacks = callbacks;
    this.tab = tab;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    List<JMenuItem> jMenuItems = new ArrayList<>();
    JMenuItem send_to_openAPI_parser = new JMenuItem(String.format("Send to %s", EXTENSION));
    send_to_openAPI_parser.addActionListener(e -> {
      for (IHttpRequestResponse selectedMessage : invocation.getSelectedMessages()) {
        IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(selectedMessage);
        String resource = requestInfo.getUrl().toString();

        try {
          OpenAPI openAPI = new Loader().process(resource);
          this.tab.populateTable(openAPI);
          this.tab.printStatus(COPYRIGHT, Color.BLACK);
        } catch (IllegalArgumentException | NullPointerException e1) {
          this.tab.printStatus(e1.getMessage(), Color.RED);
        }
      }
    });

    jMenuItems.add(send_to_openAPI_parser);

    return jMenuItems;
  }
}
