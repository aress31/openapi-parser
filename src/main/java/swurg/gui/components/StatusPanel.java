package swurg.gui.components;

import static burp.MyBurpExtension.COPYRIGHT;

import java.awt.Color;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class StatusPanel extends JPanel {

  private final JLabel statusLabel = new JLabel(COPYRIGHT);

  public StatusPanel() {
    initComponents();
  }

  private void initComponents() {
    this.statusLabel.putClientProperty("html.disable", null);
    this.add(statusLabel);
  }

  public void updateStatus(String status, Color color) {
    this.statusLabel.setForeground(color);
    this.statusLabel.setText(status);
  }
}
