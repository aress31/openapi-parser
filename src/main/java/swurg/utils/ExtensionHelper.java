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

package swurg.utils;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.CollectionUtils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import io.swagger.models.Swagger;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;

public class ExtensionHelper {

  private IExtensionHelpers burpExtensionHelpers;
  private PrintStream stdOut, stdErr;

  public ExtensionHelper(IBurpExtenderCallbacks callbacks) {
    this.burpExtensionHelpers = callbacks.getHelpers();
    this.stdOut = new PrintStream(callbacks.getStdout());
    this.stdErr = new PrintStream(callbacks.getStderr());
  }

  public IExtensionHelpers getBurpExtensionHelpers() {
    return this.burpExtensionHelpers;
  }

  private static String nullEmptyString(String input) {
    return input == null ? "" : input;
  }

  private List<String> buildHeaders(Operation operation) {
    List<String> headers = new ArrayList<>();

    headers.add(
        operation.getKey().toString() + " " + nullEmptyString(swagger.getBasePath()) + path.getKey() + " HTTP/1.1");
    headers.add("Host: " + swagger.getHost().split(":")[0]);

    if (CollectionUtils.isNotEmpty(operation.getValue().getProduces())) {
      headers.add("Accept: " + String.join(",", operation.getValue().getProduces()));
    } else if (CollectionUtils.isNotEmpty(swagger.getProduces())) {
      headers.add("Accept: " + String.join(",", swagger.getProduces()));
    }

    if (CollectionUtils.isNotEmpty(operation.getValue().getConsumes())) {
      headers.add("Content-Type: " + String.join(",", operation.getValue().getConsumes()));
    } else if (CollectionUtils.isNotEmpty(swagger.getConsumes())) {
      headers.add("Content-Type: " + String.join(",", swagger.getConsumes()));
    }

    return headers;
  }

  // TODO: This!
  public byte[] buildRequest(Operation operation) {
    // byte[] httpMessage =
    // this.burpExtensionHelpers.buildHttpMessage(buildHeaders(swagger, path,
    // operation),
    // null);

    byte[] httpMessage = this.burpExtensionHelpers.buildHttpMessage(null, null);

    if (operation != null && operation.getParameters() != null) {
      for (Parameter parameter : operation.getParameters()) {
        switch (parameter.getIn()) {
        case "body":
          httpMessage = this.burpExtensionHelpers.addParameter(httpMessage,
              this.burpExtensionHelpers.buildParameter(parameter.getName(), parameter.getSchema().getType(), (byte) 1));
          break;
        case "query":
          httpMessage = this.burpExtensionHelpers.addParameter(httpMessage,
              this.burpExtensionHelpers.buildParameter(parameter.getName(), parameter.getSchema().getType(), (byte) 0));
          break;
        default:
          throw new NullPointerException(
              "buildRequest(Operation operation) -> entered 'default' case... Please open a ticket on the GitHub repository of this project.");
        }
      }
    }

    return httpMessage;
  }
}
