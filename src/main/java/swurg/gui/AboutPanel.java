package swurg.gui;

import static burp.MyBurpExtension.COPYRIGHT;
import static burp.MyBurpExtension.EXTENSION;
import static burp.MyBurpExtension.VERSION;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.batik.swing.JSVGCanvas;

public class AboutPanel extends JPanel {

    public AboutPanel() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridy = 0;
        gbc.gridx = 0;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.CENTER;

        JPanel svgCanvas = createSvgCanvas();
        add(svgCanvas, gbc);

        gbc.gridy = 1;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weighty = 1;
        gbc.anchor = GridBagConstraints.NORTH;

        JPanel mainPanel = createMainPanel();
        add(mainPanel, gbc);

        gbc.gridy = 2;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.SOUTH;

        JPanel southPanel = createSouthPanel();
        add(southPanel, gbc);
    }

    private JPanel createSvgCanvas() {
        JPanel svgContainer = new JPanel(new BorderLayout());
        JSVGCanvas svgCanvas = new JSVGCanvas();

        svgContainer.setPreferredSize(new Dimension(512, 512)); // Set fixed size

        try {
            URI svgFileURI = getClass().getResource("/images/logo.svg").toURI();
            svgCanvas.setURI(svgFileURI.toString());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        svgCanvas.setOpaque(false);
        svgCanvas.setBackground(new Color(0, 0, 0, 0));

        svgContainer.add(svgCanvas, BorderLayout.CENTER);

        return svgContainer;
    }

    private JPanel createMainPanel() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;

        JLabel textLabel = createTextLabel();
        textLabel.setMaximumSize(new Dimension(400, textLabel.getPreferredSize().height));
        mainPanel.add(textLabel, gbc);

        gbc.gridy++;
        JPanel buttonPanel = createButtonPanel();
        mainPanel.add(buttonPanel, gbc);

        return mainPanel;
    }

    private JLabel createTextLabel() {
        String formattedText = String.format(
                "<html>"
                        + "<body style='text-align: justify; text-justify: inter-word; font-family: Arial, sans-serif;'>"
                        + "<ul><li>Current version:</b> <em>%s</em></li></ul>"
                        + "<br/>"
                        + "<p>%s is a handy tool for testing OpenAPI-based APIs using Burp Suite. The developer behind this project is <b>Alexandre Teyar</b>, Managing Director at <b>Aegis Cyber</b>.</p>"
                        + "<br/>"
                        + "<p>Your feedback matters to us! If you have suggestions for new features, enhancements, or improvements, feel free to submit a ticket and share your thoughts. If you'd like to contribute, <b>pull requests are always welcome!</b></p>"
                        + "<br/>"
                        + "<p>If you've used %s and found it helpful for testing OpenAPI-based APIs, please consider showing your support by giving the repository a star and rating it on the BApp Store. We appreciate your support!</p>"
                        + "<br/>"
                        + "<p>We'd like to express our gratitude to all GitHub contributors who have dedicated their time and expertise to making %s a better tool for the community!</p>"
                        + "</body>"
                        + "</html>",
                VERSION, EXTENSION, EXTENSION, EXTENSION);
        JLabel textLabel = new JLabel(formattedText);
        textLabel.putClientProperty("html.disable", null);
        return textLabel;
    }

    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 5, 5, 5);

        Map<String, String> buttonMap = Map.of(
                "<html>Get in touch with <b>Aegis Cyber</b></html>", "https://www.aegiscyber.co.uk",
                "<html>Connect with me on <b>LinkedIn</b></html>", "https://www.linkedin.com/in/alexandre-teyar",
                "<html>Follow me on <b>GitHub</b></html>", "https://github.com/aress31",
                "<html>Submit a <b>pull request</b> or report a <b>bug</b></html>", "https://github.com/aress31/swurg");

        for (Map.Entry<String, String> entry : buttonMap.entrySet()) {
            JButton button = new JButton();
            button.putClientProperty("html.disable", null);
            button.setPreferredSize(new Dimension(192, 40));
            button.setText(entry.getKey());
            button.addActionListener(e -> {
                try {
                    Desktop.getDesktop().browse(new URI(entry.getValue()));
                } catch (IOException | URISyntaxException ex) {
                    // Do nothing
                }
            });

            gbc.gridwidth = GridBagConstraints.REMAINDER; // Set gridwidth to REMAINDER
            gbc.insets = new Insets(5, 5, (gbc.gridy == buttonMap.size() - 1 ? 20 : 5), 5); // Add extra space before
                                                                                            // last button
            buttonPanel.add(button, gbc);
            gbc.gridy++; // Increment gridy
        }

        return buttonPanel;
    }

    private JPanel createSouthPanel() {
        JPanel southPanel = new JPanel();
        JLabel copyrightLabel = createCopyrightLabel();
        southPanel.add(copyrightLabel);
        return southPanel;
    }

    private JLabel createCopyrightLabel() {
        JLabel copyrightLabel = new JLabel(COPYRIGHT);
        copyrightLabel.putClientProperty("html.disable", null);
        return copyrightLabel;
    }
}
