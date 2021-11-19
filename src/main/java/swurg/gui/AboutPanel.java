/*
#    Copyright (C) 2016-2021 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. F
*/

package swurg.gui;

import static burp.BurpExtender.COPYRIGHT;
import static burp.BurpExtender.EXTENSION;
import static burp.BurpExtender.VERSION;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class AboutPanel extends JPanel {

    public AboutPanel() {
        initComponents();
    }

    private void initComponents() {
        this.setLayout(new BorderLayout());

        JLabel aboutLabel = new JLabel("<html>" + "<body style=\"text-align: justify; text-justify: inter-word;\">"
                + "<p>" + EXTENSION
                + " has been developped by <b>Alexandre Teyar</b>, Managing Director at <b>Aegis Cyber</b>.</p>" + "<p>"
                + EXTENSION + " version: <em>" + VERSION + "</em></p>" + "<br/>"
                + "<p>Would you like to see new feature(s) implemented? Raise a ticket and share your thoughts.</p>"
                + "<p>Would you like to actively contribute to this project? PRs are <b>ALWAYS</b> welcome!</p>"
                + "<br/>" + "<p>If you use " + EXTENSION
                + " and like it, show your appreciation by giving its repository a star and rating"
                + "it on BApp Store.</p>" + "<br/>" + "<p>Special thanks to all the GitHub contributors!</p>"
                + "</body>" + "</html>");

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new Insets(4, 4, 4, 4);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;

        int index = 1;

        JPanel aboutButton = new JPanel(new GridBagLayout());

        for (Map.Entry<String, String> entry : Map.of("<html>Talk With <b>Aegis Cyber</b></html>",
                "www.aegiscyber.co.uk", "<html>Connect <b>(With Me)<b> on <b>LinkedIn</b></html>",
                "www.linkedin.com/in/alexandre-teyar", "<html>Follow <b>(Me)</b> on <b>GitHub</b></html>",
                "github.com/aress31", "<html>Submit <b>PR</b>/Report a <b>Bug</b></html>", "github.com/aress31/swurg")
                .entrySet()) {
            JButton x = new JButton();
            x.setPreferredSize(new Dimension(192, 40));
            x.setText(entry.getKey());
            x.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    try {
                        java.awt.Desktop.getDesktop().browse(new URI(entry.getValue()));
                    } catch (IOException | URISyntaxException e1) {
                        // Do nothing
                    }
                }
            });

            if (index % 2 == 0) {
                gridBagConstraints.gridx = 1;
            } else {
                gridBagConstraints.gridx = 0;
                gridBagConstraints.gridy++;
            }

            aboutButton.add(x, gridBagConstraints);

            index++;
        }

        JPanel aboutPanel = new JPanel(new GridBagLayout());

        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new Insets(4, 8, 4, 8);
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 0;

        aboutPanel.add(aboutLabel, gridBagConstraints);

        gridBagConstraints.gridy++;
        gridBagConstraints.fill = GridBagConstraints.NONE;
        gridBagConstraints.insets = new Insets(0, 4, 0, 4);
        gridBagConstraints.weightx = 0;
        gridBagConstraints.weighty = 1.0;

        aboutPanel.add(aboutButton, gridBagConstraints);

        aboutPanel.setPreferredSize(new Dimension(0, aboutPanel.getPreferredSize().height + 64));

        JPanel southPanel = new JPanel();
        southPanel.add(new JLabel(COPYRIGHT));

        this.add(aboutPanel);
        this.add(southPanel, BorderLayout.SOUTH);
    }
}
