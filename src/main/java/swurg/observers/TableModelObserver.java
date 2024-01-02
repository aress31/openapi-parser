package swurg.observers;

import java.util.List;

import burp.http.MyHttpRequest;

public interface TableModelObserver {
    void onMyHttpRequestsUpdate(int event, List<MyHttpRequest> myHttpRequests);
}
