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
import io.swagger.models.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ExtensionHelper {
    private IExtensionHelpers burpHelpers;

    public ExtensionHelper(IBurpExtenderCallbacks callbacks) {
        this.burpHelpers = callbacks.getHelpers();
    }

    public boolean getUseHttps(Scheme scheme) {
        boolean useHttps;

        useHttps = scheme.toValue().toUpperCase().equals("HTTPS") || scheme.toValue().toUpperCase().equals("WSS");

        return useHttps;
    }

    public int getPort(Swagger swagger, Scheme scheme) {
        int port;

        if (swagger.getHost().split(":").length > 1) {
            port = Integer.valueOf(swagger.getHost().split(":")[1]);
        } else {
            if (scheme.toValue().toUpperCase().equals("HTTPS")) {
                port = 443;
            } else {
                // default value to return
                port = 80;
            }
        }

        return port;
    }

    public byte[] buildRequest(Swagger swagger, Map.Entry<String, Path> path, Map.Entry<HttpMethod, Operation> operation) {
        List<String> headers = this.buildHeaders(swagger, path, operation);
        byte[] httpMessage = this.burpHelpers.buildHttpMessage(headers, null);

        for (io.swagger.models.parameters.Parameter parameter : operation.getValue().getParameters()) {
            if (parameter.getIn().equals("query")) {
                httpMessage = this.burpHelpers.addParameter(httpMessage, burpHelpers.buildParameter(parameter.getName(), "fuzzMe", (byte) 0));
            } else if (parameter.getIn().equals("body")) {
                httpMessage = this.burpHelpers.addParameter(httpMessage, burpHelpers.buildParameter(parameter.getName(), "fuzzMe", (byte) 1));
            }
        }

        return httpMessage;
    }

    private List<String> buildHeaders(Swagger swagger, Map.Entry<String, Path> path, Map.Entry<HttpMethod, Operation> operation) {
        List<String> headers = new ArrayList<>();

        headers.add(operation.getKey().toString() + " " + path.getKey() + " HTTP/1.1");
        headers.add("Host: " + swagger.getHost().split(":")[0]);

        if (operation.getValue().getProduces() != null && !operation.getValue().getProduces().isEmpty()) {
            headers.add("Accept: " + String.join(",", operation.getValue().getProduces()));
        } else if (swagger.getProduces() != null && !swagger.getProduces().isEmpty()) {
            headers.add("Accept: " + String.join(",", swagger.getProduces()));
        }

        if (operation.getValue().getConsumes() != null && !operation.getValue().getConsumes().isEmpty()) {
            headers.add("Content-Type: " + String.join(",", operation.getValue().getConsumes()));
        } else if (swagger.getConsumes() != null && !swagger.getConsumes().isEmpty()) {
            headers.add("Content-Type: " + String.join(",", swagger.getConsumes()));
        }

        return headers;
    }
}
