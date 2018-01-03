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

public class Loader {

    public Swagger process(File file) {
        if (file == null) {
            throw new IllegalArgumentException("No file specified");
        }

        if (!file.exists()) {
            throw new IllegalArgumentException("File doesn't exist!");
        }

        return new SwaggerParser().read(file.getAbsolutePath());
    }
}
