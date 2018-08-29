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

public class HttpRequestResponse implements IHttpRequestResponse {

  private IHttpService httpService;
  private boolean useHttps;
  private byte[] request;

  public HttpRequestResponse(
      IHttpService httpService, boolean useHttps, byte[] request
  ) {
    this.httpService = httpService;
    this.useHttps = useHttps;
    this.request = request;
  }

  public boolean isUseHttps() {
    return useHttps;
  }

  @Override
  public byte[] getRequest() {
    return this.request;
  }

  @Override
  public void setRequest(byte[] message) {
  }

  @Override
  public byte[] getResponse() {
    return new byte[0];
  }

  @Override
  public void setResponse(byte[] message) {
  }

  @Override
  public String getComment() {
    return null;
  }

  @Override
  public void setComment(String comment) {
  }

  @Override
  public String getHighlight() {
    return null;
  }

  @Override
  public void setHighlight(String color) {
  }

  @Override
  public IHttpService getHttpService() {
    return this.httpService;
  }

  @Override
  public void setHttpService(IHttpService httpService) {
  }
}
