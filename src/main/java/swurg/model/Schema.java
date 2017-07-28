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

import java.util.List;
import java.util.Map;

public class Schema {
	private String type;
    private String $ref;
    private List<String> items;
    private Map<String, Property> properties;

	public Schema(String type, String $ref, Map<String, Property> properties) {
		this.type = type;
		this.properties = properties;
    }

    public String getType() {
    	return this.type;
    }
    
    public String getRef() {
    	return this.$ref;
    }

    public Map<String, Property> getProperties() {
    	return this.properties;
    }
}
