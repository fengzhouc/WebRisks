package com.alumm0x.listensers;

import java.util.List;
import java.util.ArrayList;

import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;

public class HttpRequestResponseWithMarkers implements IHttpRequestResponseWithMarkers {

    IHttpRequestResponse actual;
    List<int[]> requestMarkers = new ArrayList<>();
    List<int[]> responseMarkers = new ArrayList<>();

    public HttpRequestResponseWithMarkers(IHttpRequestResponse actual) {
        this.actual = actual;
    }

    public HttpRequestResponseWithMarkers(){    }

    /**
     * 在请求中添加内容标记，以高亮显示
     */
    public void setRequestMarker(String... highlightedValues){
        byte[] requestBytes = actual.getRequest();
        for(String value : highlightedValues) {
            int startIndex = indexOf(requestBytes,value.getBytes());
            if(startIndex != -1) {
                int endIndex = value.length();
                responseMarkers.add(new int[] {startIndex,startIndex+endIndex});
            }
        }
    }

    /**
     * 在响应中添加内容标记，以高亮显示
     */
    public void setResponseMarker(String... highlightedValues){
        byte[] responseBytes = actual.getResponse();
        for(String value : highlightedValues) {
            int startIndex = indexOf(responseBytes,value.getBytes());
            if(startIndex != -1) {
                int endIndex = value.length();
                responseMarkers.add(new int[] {startIndex,startIndex+endIndex});
            }
        }
    }

    @Override
    public byte[] getRequest() {
        return actual.getRequest();
    }

    @Override
    public void setRequest(byte[] message) {
        actual.setRequest(message);
    }

    @Override
    public byte[] getResponse() {
        return actual.getResponse();
    }

    @Override
    public void setResponse(byte[] message) {
        actual.setResponse(message);
    }

    @Override
    public String getComment() {
        return actual.getComment();
    }

    @Override
    public void setComment(String comment) {
        actual.setComment(comment);
    }

    @Override
    public String getHighlight() {
        return actual.getHighlight();
    }

    @Override
    public void setHighlight(String color) {
        actual.setHighlight(color);
    }

    @Override
    public IHttpService getHttpService() {
        return actual.getHttpService();
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        actual.setHttpService(httpService);
    }

    @Override
    public List<int[]> getRequestMarkers() {
        return requestMarkers;
    }

    @Override
    public List<int[]> getResponseMarkers() {
        return responseMarkers;
    }


    /**
     * 根据需要高亮的内容，在请求或响应中找到其位置
     * @param outerArray
     * @param smallerArray
     * @return
     */
    public static int indexOf(byte[] outerArray, byte[] smallerArray) {
        for(int i = 0; i < outerArray.length - smallerArray.length+1; ++i) {
            boolean found = true;
            for(int j = 0; j < smallerArray.length; ++j) {
                if (outerArray[i+j] != smallerArray[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }
    
}
