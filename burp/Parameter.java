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

package burp;

import com.google.gson.JsonObject;

public class Parameter {
    private String name;
    private String in;
    private Boolean required;
    private String type;
    private JsonObject schema;

    public Parameter(String name, String in, Boolean required, String type, JsonObject schema) {
        this.name = name;
        this.in = in;
        this.required = required;
        this.type = type;
        this.schema = schema;
    }

    public String getName() {
        return this.name;
    }

    public String getIn() {
        return this.in;
    }

    public Boolean getRequired() {
        return this.required;
    }

    public String getType() {
        return this.type;
    }

    public JsonObject getSchema() {
        return this.schema;
    }
}