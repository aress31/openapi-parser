package burp;

import java.util.Calendar;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import swurg.gui.MainTabGroup;

public class MyBurpExtension implements BurpExtension {

  public static final String COPYRIGHT = String.format(
      "<html>Copyright \u00a9 2016 - %s Alexandre Teyar, Aegis Cyber &lt;<a href=\"https://aegiscyber.co.uk\">www.aegiscyber.co.uk</a>&gt;. All Rights Reserved.</html>",
      Calendar.getInstance().get(Calendar.YEAR));
  public static final String EXTENSION = "OpenAPI Parser";
  public static final String VERSION = "4.1";

  @Override
  public void initialize(MontoyaApi montoyaApi) {
    montoyaApi.extension().setName(EXTENSION);

    Logging logging = montoyaApi.logging();

    MainTabGroup mainTabGroup = new MainTabGroup(montoyaApi);
    montoyaApi.userInterface().applyThemeToComponent(mainTabGroup);

    montoyaApi.userInterface().registerSuiteTab(EXTENSION, mainTabGroup);
    logging.logToOutput(String.format("'%s' tab initialised", EXTENSION));

    ContextMenuItemsProvider myContextMenuItemsProvider = new MyContextMenuItemsProvider(montoyaApi,
        mainTabGroup.getParserPanel());

    montoyaApi.userInterface()
        .registerContextMenuItemsProvider(myContextMenuItemsProvider);
    logging.logToOutput(String.format("'Send to %s' option added to the context menu", EXTENSION));

    montoyaApi.http().registerHttpHandler(mainTabGroup.getParametersPanel());
    logging.logToOutput("HTTPListener registered");
  }
}
