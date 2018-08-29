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

package swurg.process;

import io.swagger.models.Swagger;
import io.swagger.parser.SwaggerParser;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

public class Loader {

  public Swagger process(String resource) {
    if (resource == null) {
      throw new IllegalArgumentException();
    }

    if (new File(resource).exists()) {
      assert true;
    } else {
      try {
        new URL(resource).toURI();
      } catch (MalformedURLException | URISyntaxException e) {
        throw new IllegalArgumentException(e);
      }
    }

    Swagger swagger = new SwaggerParser().read(resource);

    if (swagger == null) {
      throw new NullPointerException();
    } else {
      return swagger;
    }
  }
}
