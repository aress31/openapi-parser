package burp;

import io.swagger.models.Swagger;
import swurg.process.Loader;
import swurg.ui.Tab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

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
        JMenuItem send_to_swagger_parser = new JMenuItem("Send to Swagger Parser");
        send_to_swagger_parser.addActionListener(e -> {
            for (IHttpRequestResponse selectedMessage : invocation.getSelectedMessages()) {
                IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(selectedMessage);
                Swagger swagger = new Loader().process(requestInfo.getUrl().toString());
                tab.loadSwagger(swagger);
            }
        });

        jMenuItems.add(send_to_swagger_parser);

        return jMenuItems;
    }
}
