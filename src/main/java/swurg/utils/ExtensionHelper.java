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
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.MediaType;
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

  private List<String> buildHeaders(URI uri, Map.Entry<String, PathItem> pathItem,
      Map.Entry<String, Operation> operation) {
    List<String> headers = new ArrayList<>();

    headers.add(operation.getKey() + " " + pathItem.getKey() + " HTTP/1.1");
    headers.add("Host: " + uri.getHost());

    if (operation.getValue().getResponses() != null && operation.getValue().getResponses().get("200") != null) {
      StringJoiner stringJoiner = new StringJoiner(", ");

      for (Map.Entry<String, MediaType> response : operation.getValue().getResponses().get("200").getContent()
          .entrySet()) {
        stringJoiner.add(response.getKey());
      }

      headers.add("Accept: " + stringJoiner.toString());
    }

    if (operation.getValue().getRequestBody() != null && operation.getValue().getRequestBody().getContent() != null) {
      StringJoiner stringJoiner = new StringJoiner(", ");

      for (Map.Entry<String, MediaType> requestBody : operation.getValue().getRequestBody().getContent().entrySet()) {
        stringJoiner.add(requestBody.getKey());
      }

      headers.add("Content-Type: " + stringJoiner.toString());
    }

    if (operation.getValue().getParameters() != null) {
      for (Parameter parameter : operation.getValue().getParameters()) {
        if (parameter != null && parameter.getIn() != null) {
          switch (parameter.getIn()) {
          case "header":
            headers.add(parameter.getName() + " " + parameter.getSchema().getType());
            break;
          case "path":
            // TODO: If I want to replace let's say {petId} in the path with {int} need to
            // use a regex to replace parameter.getName() with
            // parameter.getSchema().getType()
            break;
          default:
            break;
          }
        }
      }
    }

    return headers;
  }

  public byte[] buildRequest(URI uri, Map.Entry<String, PathItem> pathItem, Map.Entry<String, Operation> operation) {
    List<String> headers = buildHeaders(uri, pathItem, operation);
    byte[] httpMessage = this.burpExtensionHelpers.buildHttpMessage(headers, null);

    if (operation.getValue().getParameters() != null) {
      for (Parameter parameter : operation.getValue().getParameters()) {
        if (parameter != null && parameter.getIn() != null) {
          switch (parameter.getIn()) {
          // TODO: Do not seem to be used in OAS v3 but still...
          case "body":
            httpMessage = this.burpExtensionHelpers.addParameter(httpMessage, this.burpExtensionHelpers
                .buildParameter(parameter.getName(), "{" + parameter.getSchema().getType() + "}", (byte) 1));
            break;
          case "header":
            // Handled in buildHeaders(URI uri, Map.Entry<String, PathItem> pathItem,
            // Map.Entry<String, Operation> operation)
            break;
          case "path":
            // Handled in buildHeaders(URI uri, Map.Entry<String, PathItem> pathItem,
            // Map.Entry<String, Operation> operation)
            break;
          case "query":
            httpMessage = this.burpExtensionHelpers.addParameter(httpMessage, this.burpExtensionHelpers
                .buildParameter(parameter.getName(), "{" + parameter.getSchema().getType() + "}", (byte) 0));
            break;
          default:
            throw new NullPointerException(
                "buildRequest(URI uri, Map.Entry<String, PathItem> pathItem, Map.Entry<String, Operation> operation) -> entered 'default' case... Please open a ticket on the GitHub repository of this project.");
          }
        }
      }
    }

    return httpMessage;
  }
}
