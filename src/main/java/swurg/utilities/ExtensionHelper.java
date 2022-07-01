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

package swurg.utilities;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponses;

public class ExtensionHelper {

  private IBurpExtenderCallbacks callbacks;

  public ExtensionHelper(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  private String parseParameterValue(Schema schema) {
    String value;

    if (schema.getExample() != null) {
      value = schema.getExample().toString();
    } else if (schema.getEnum() != null) {
      value = schema.getEnum().toString().replace(" ", "").replace(System.lineSeparator(), "");
    } else if (schema.getFormat() != null) {
      value = "{" + schema.getType() + "->" + schema.getFormat() + "}";
    } else {
      value = schema.getType() == null ? "{object}" : "{" + schema.getType() + "}";
    }

    return value;
  }

  private byte[] parseParameter(byte[] httpMessage, String parameterName, Schema schema, byte parameterType) {
    httpMessage = this.callbacks.getHelpers().addParameter(httpMessage,
        this.callbacks.getHelpers().buildParameter(parameterName, parseParameterValue(schema), parameterType));

    return httpMessage;
  }

  // TODO: Make this function recursive to get informaiton about nested parameters
  private byte[] parseBodyParameters(byte[] httpMessage, OpenAPI openAPI, RequestBody requestBody) {
    MediaType mediaType = requestBody.getContent().entrySet().stream().findFirst().get().getValue();

    if (mediaType.getSchema().get$ref() != null) {
      String href = mediaType.getSchema().get$ref();
      String[] deconstructedHref = href.split("/");
      String formattedHref = deconstructedHref[deconstructedHref.length - 1];

      Schema schema = openAPI.getComponents().getSchemas().get(formattedHref);

      Map<String, Schema> properties = schema.getProperties();

      for (Map.Entry<String, Schema> property : properties.entrySet()) {
        httpMessage = parseParameter(httpMessage, property.getKey(), property.getValue(),
            convertContentTypeToBurpCode(parseContentType(requestBody)));
      }
    }

    return httpMessage;
  }

  private String parseAccept(ApiResponses responses) {
    StringJoiner stringJoiner = new StringJoiner(",");

    if (responses != null && responses.get("200") != null) {
      for (Map.Entry<String, MediaType> response : responses.get("200").getContent().entrySet()) {
        stringJoiner.add(response.getKey());
      }
    }

    return stringJoiner.toString();
  }

  private byte convertContentTypeToBurpCode(String contentType) {
    byte result = IParameter.PARAM_BODY;

    switch (contentType) {
      // Not yet supported
      case ("application/json"): {
        // result = IParameter.PARAM_JSON;
        break;
      }
      case ("application/octet-stream"): {
        break;
      }
      case ("application/x-www-form-urlencoded"): {
        break;
      }
      // Not yet supported
      case ("application/xml"): {
        // result = IParameter.PARAM_XML;
        break;
      }
      case ("multipart/form-data"): {
        break;
      }
      default: {
        break;
      }
    }

    return result;
  }

  private String parseContentType(RequestBody requestBody) {
    String contentType = "";

    if (requestBody != null && requestBody.getContent() != null) {
      contentType = requestBody.getContent().entrySet().stream().findFirst().get().getKey();
    }

    return contentType;
  }

  private List<String> buildHeaders(URI uri, String httpMethod, String path, List<Parameter> parameters,
      RequestBody requestBody, ApiResponses responses) {
    List<String> headers = new ArrayList<>();

    headers.add(httpMethod + " " + path + " HTTP/1.1");
    headers.add("Host: " + uri.getHost());
    if (!parseAccept(responses).isEmpty())
      headers.add("Accept: " + parseAccept(responses));
    if (!parseContentType(requestBody).isEmpty())
      headers.add("Content-Type: " + parseContentType(requestBody));

    // TODO: Burp API does not yet support header parameters
    if (parameters != null) {
      for (Parameter parameter : parameters) {
        if (parameter != null && Arrays.asList("header").contains(parameter.getIn())) {
          headers.add(parameter.getName() + ": " + parseParameterValue(parameter.getSchema()));
        }
      }
    }

    return headers;
  }

  public byte[] buildRequest(URI uri, String path, OpenAPI openAPI, Map.Entry<String, Operation> operation) {
    List<String> headers = buildHeaders(uri, operation.getKey(), path, operation.getValue().getParameters(),
        operation.getValue().getRequestBody(), operation.getValue().getResponses());

    byte[] httpMessage = this.callbacks.getHelpers().buildHttpMessage(headers, null);

    if (operation.getValue().getParameters() != null) {
      for (Parameter parameter : operation.getValue().getParameters()) {
        if (parameter != null && Arrays.asList("query").contains(parameter.getIn())) {
          httpMessage = parseParameter(httpMessage, parameter.getName(), parameter.getSchema(), IParameter.PARAM_URL);
        }
      }
    }

    if (operation.getValue().getRequestBody() != null && operation.getValue().getRequestBody().getContent() != null) {
      httpMessage = parseBodyParameters(httpMessage, openAPI, operation.getValue().getRequestBody());
    }

    return httpMessage;
  }
}
