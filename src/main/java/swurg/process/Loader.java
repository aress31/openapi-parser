/*
#    Copyright (C) 2016-2022 Alexandre Teyar

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

package swurg.process;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

import org.apache.http.client.utils.URIBuilder;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import swurg.utilities.ExtensionHelper;
import swurg.utilities.LogEntry;

public class Loader {

  private ExtensionHelper extensionHelper;

  private IBurpExtenderCallbacks callbacks;

  public Loader(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    this.extensionHelper = new ExtensionHelper(callbacks);
  }

  public OpenAPI processOpenAPI(String resource) {
    SwaggerParseResult result = new SwaggerParseResult();

    try {
      Path filePath = Paths.get(resource);

      if (Files.exists(filePath) && !Files.isDirectory(filePath)) {
        // File case
        String openAPIasString = Files.readString(Paths.get(resource), StandardCharsets.UTF_8);
        result = new OpenAPIParser().readContents(openAPIasString, null, null);
      } else {
        throw new InvalidPathException(resource, "File does not exist on the system or is not a file.");
      }
    } catch (InvalidPathException e) {
      // URL case
      result = new OpenAPIParser().readLocation(resource, null, null);
    } catch (IOException e) {
      callbacks.printError(String.format("%s -> %s", this.getClass().getName(), e.getMessage()));
    }

    if (result.getMessages() != null && !result.getMessages().isEmpty()) {
      callbacks.printError(String.format("%s -> %s", this.getClass().getName(), result.getMessages()));
      throw new NullPointerException(result.getMessages().toString());
    }

    return result.getOpenAPI();
  }

  public List<LogEntry> parseOpenAPI(OpenAPI openAPI) {
    List<LogEntry> logEntries = new ArrayList<>();

    for (Server server : openAPI.getServers()) {
      for (Map.Entry<String, PathItem> pathItem : openAPI.getPaths().entrySet()) {
        Map<String, Operation> operationMap = new HashMap<>();
        operationMap.put("DELETE", pathItem.getValue().getDelete());
        operationMap.put("GET", pathItem.getValue().getGet());
        operationMap.put("HEAD", pathItem.getValue().getHead());
        operationMap.put("PATCH", pathItem.getValue().getPatch());
        operationMap.put("POST", pathItem.getValue().getPost());
        operationMap.put("PUT", pathItem.getValue().getPut());
        operationMap.put("TRACE", pathItem.getValue().getTrace());

        // create different maps for different methods merge them and iterate them
        for (Map.Entry<String, Operation> operation : operationMap.entrySet()) {
          if (operation.getValue() != null) {
            StringJoiner stringJoiner = new StringJoiner(", ");

            if (operation.getValue().getParameters() != null) {
              for (Parameter parameter : operation.getValue().getParameters()) {
                stringJoiner.add(parameter.getName());
              }
            }

            try {
              URI uri = new URI(server.getUrl());

              String scheme = Objects.requireNonNullElse(uri.getScheme(), "http");
              String host = Objects.requireNonNullElse(uri.getHost(), "127.0.0.1");
              int port = uri.getPort() == -1 ? (scheme.equals("http") ? 80 : 443) : 80;

              URI newUri = new URIBuilder(uri).setScheme(scheme).setHost(host).setPort(port).build();

              HttpRequestResponse httpRequestResponse = new HttpRequestResponse(
                  this.callbacks.getHelpers().buildHttpService(newUri.getHost(), newUri.getPort(),
                      newUri.getPort() == 443),
                  newUri.getPort() == 443,
                  this.extensionHelper.buildRequest(newUri, newUri.getPath(), openAPI, operation));

              logEntries.add(new LogEntry(httpRequestResponse, operation.getKey(), newUri.getHost(), pathItem.getKey(),
                  stringJoiner.toString(), operation.getValue().getDescription()));
            } catch (URISyntaxException e) {
              callbacks.printError(String.format("%s -> %s", this.getClass().getName(), e.getMessage()));
              throw new NullPointerException(e.getMessage());
            }
          }
        }
      }
    }

    return logEntries;
  }
}
