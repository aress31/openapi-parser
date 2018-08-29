/*
#    Copyright (C) 2016 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package burp;

import swurg.ui.Tab;

public class BurpExtender implements IBurpExtender {

  public static String COPYRIGHT = "Copyright \u00a9 2016 - 2018 Alexandre Teyar All Rights Reserved";
  public static String EXTENSION = "Swagger Parser";

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    Tab tab = new Tab(callbacks);
    ContextMenuFactory contextMenuFactory = new ContextMenuFactory(callbacks, tab);

    callbacks.setExtensionName(EXTENSION);
    callbacks.addSuiteTab(tab);
    callbacks.printOutput(String.format("%s initialised", EXTENSION));

    callbacks.registerContextMenuFactory(contextMenuFactory);
    callbacks.printOutput(String.format("%s added to the context menu", EXTENSION));
  }
}
