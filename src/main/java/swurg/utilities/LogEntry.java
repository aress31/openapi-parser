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
#    limitations under the License. 
*/

package swurg.utilities;

import burp.HttpRequestResponse;

public class LogEntry {
    private HttpRequestResponse httpRequestResponse;
    private String description;
    private String httpMethod;
    private String pathItem;
    private String parameters;
    private String server;

    // TODO: Derive most of the constructors from httpRequestResponse
    public LogEntry(HttpRequestResponse httpRequestResponse, String httpMethod, String server, String pathItem,
            String parameters, String description) {
        this.httpRequestResponse = httpRequestResponse;
        this.server = server;
        this.pathItem = pathItem;
        this.parameters = parameters;
        this.description = description;
        this.httpMethod = httpMethod;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        return this.httpRequestResponse;
    }

    public String getHttpMethod() {
        return this.httpMethod;
    }

    public String getServer() {
        return this.server;
    }

    public String getPathItem() {
        return this.pathItem;
    }

    public String getDescription() {
        return this.description;
    }

    public String getParameters() {
        return this.parameters;
    }
}
