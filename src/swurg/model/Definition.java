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

package swurg.model;

import java.util.Map;

public class Definition {
    private String type;
    private Map<String, Property> properties;

       public Definition(String type, Map<String, Property> properties) {
        this.type = type;
        this.properties = properties;
    }

    public String getType() {
        return this.type;
    }

    public Map<String, Property> getProperties() {
        return this.properties;
    }
}