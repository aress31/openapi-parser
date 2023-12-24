package swurg.gui.components;

import static burp.MyBurpExtension.COPYRIGHT;

import java.awt.Color;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class StatusPanel extends JPanel {

  private JLabel statusLabel;

  public StatusPanel() {
    statusLabel = new JLabel(COPYRIGHT);

    initComponents();
  }

  private void initComponents() {
    statusLabel.putClientProperty("html.disable", null);
    this.add(statusLabel);
  }

  public void updateStatus(String status, Color color) {
    statusLabel.setForeground(color);
    statusLabel.setText(status);
  }
}
