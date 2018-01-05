package burp;

import javax.swing.*;
import java.util.List;

public class ContextMenuFactory implements IContextMenuFactory {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> jMenuItems = null;

        JMenuItem send_to_swagger_parser = new JMenuItem("Send to Swagger Parser");
        send_to_swagger_parser.addActionListener(e -> {
        });

        jMenuItems.add(send_to_swagger_parser);

        return jMenuItems;
    }
}
