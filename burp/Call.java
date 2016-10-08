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

import java.util.List;

public class Call {
	private String type;
	private List<String> consumes;
	private List<String> produces;
	private List<Parameter> parameters;
    private JsonObject responses;

	public Call(List<String> consumes, List<String> produces, List<Parameter> parameters, JsonObject responses) {
		this.consumes = consumes;
		this.produces = produces;
		this.parameters = parameters;
		this.responses = responses;
    }

    public void setType(String type) {
    	this.type = type;
    }

    public String getType() {
    	return this.type;
    }
    
    public List<String> getConsumes() {
    	return this.consumes;
    }
    
    public List<String> getProduces() {
    	return this.produces;
    }
    
    public List<Parameter> getParameters() {
    	return this.parameters;
    }
    
    public JsonObject getResponses() {
    	return this.responses;
    }

    public class Parameter {
        private String name;
        private String in;
        private Boolean required;
        private String type;

        public Parameter(String name, String in, Boolean required, String type) {
            this.name = name;
            this.in = in;
            this.required = required;
            this.type = type;
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
    }
}