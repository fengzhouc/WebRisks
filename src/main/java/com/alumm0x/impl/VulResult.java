package com.alumm0x.impl;

import com.alumm0x.listensers.HttpRequestResponseWithMarkers;


public class VulResult {

    final String message;
    final short status;
    final HttpRequestResponseWithMarkers httpRequestResponse;
    final String host;
    final String path;
    public final int id;

    public VulResult(int id, String message, short status, HttpRequestResponseWithMarkers httpRequestResponse, String path, String host) {
        this.message = message;
        this.status = status;
        this.httpRequestResponse = httpRequestResponse;
        this.host = host;
        this.path = path;
        this.id = id;
    }
}
