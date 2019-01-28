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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import io.swagger.models.HttpMethod;
import io.swagger.models.Operation;
import io.swagger.models.Path;
import io.swagger.models.Scheme;
import io.swagger.models.Swagger;
import io.swagger.models.parameters.AbstractSerializableParameter;
import io.swagger.models.parameters.Parameter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections4.CollectionUtils;

public class ExtensionHelper {

  private IExtensionHelpers burpExtensionHelpers;

  public ExtensionHelper(IBurpExtenderCallbacks callbacks) {
    this.burpExtensionHelpers = callbacks.getHelpers();
  }

  public IExtensionHelpers getBurpExtensionHelpers() {
    return this.burpExtensionHelpers;
  }

  public int getPort(
      Swagger swagger, Scheme scheme
  ) {
    int port;

    if (swagger.getHost().split(":").length > 1) {
      port = Integer.valueOf(swagger.getHost().split(":")[1]);
    } else {
      if (scheme.toValue().toUpperCase().equals("HTTPS")) {
        port = 443;
      } else {
        port = 80;
      }
    }

    return port;
  }

  public boolean isUseHttps(Scheme scheme) {
    boolean useHttps;

    useHttps = scheme.toValue().toUpperCase().equals("HTTPS") || scheme.toValue().toUpperCase()
        .equals("WSS");

    return useHttps;
  }

  private static String nullEmptyString(String input) {
    return input == null ? "" : input;
  }

  private List<String> buildHeaders(
      Swagger swagger, Map.Entry<String, Path> path, Map.Entry<HttpMethod, Operation> operation
  ) {
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

  public byte[] buildRequest(
      Swagger swagger, Map.Entry<String, Path> path, Map.Entry<HttpMethod, Operation> operation
  ) {
    List<String> headers = buildHeaders(swagger, path, operation);
    byte[] httpMessage = this.burpExtensionHelpers.buildHttpMessage(headers, null);

    for (Parameter parameter : operation.getValue().getParameters()) {
      String type;

      if (parameter instanceof AbstractSerializableParameter) {
        AbstractSerializableParameter abstractSerializableParameter = (AbstractSerializableParameter) parameter;
        type = abstractSerializableParameter.getType();
      } else {
        type = "not-accessible";
      }

      switch (parameter.getIn()) {
        case "body":
          httpMessage = this.burpExtensionHelpers
              .addParameter(httpMessage, this.burpExtensionHelpers
                  .buildParameter(parameter.getName(), type, (byte) 1));
        case "query":
          httpMessage = this.burpExtensionHelpers
              .addParameter(httpMessage, this.burpExtensionHelpers
                  .buildParameter(parameter.getName(), type, (byte) 0));
      }
    }

    return httpMessage;
  }
}
