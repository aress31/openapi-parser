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

package swurg.process;

import java.io.File;

import com.google.common.base.Strings;

import burp.IBurpExtenderCallbacks;
import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.core.models.SwaggerParseResult;

public class Loader {

  public OpenAPI process(IBurpExtenderCallbacks callbacks, String resource) {
    SwaggerParseResult result;

    if (Strings.isNullOrEmpty(resource))
      throw new IllegalArgumentException("No file or URL specified");

    if (new File(resource).exists()) {
      result = new OpenAPIParser().readContents(resource, null, null);
    } else {
      result = new OpenAPIParser().readLocation(resource, null, null);
    }

    OpenAPI openAPI = result.getOpenAPI();

    // validation errors and warnings
    if (result.getMessages() != null && !result.getMessages().isEmpty()) {
      callbacks.printError(result.getMessages().toString());
      throw new NullPointerException(String.format("%s", result.getMessages()));
    }

    return openAPI;
  }
}
