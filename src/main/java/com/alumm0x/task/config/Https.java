package com.alumm0x.task.config;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class Https extends VulTaskImpl {


    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new Https(requestResponse);
    }

    private Https(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            String protocol = BurpReqRespTools.getProtocol(requestResponse);
            if (protocol.toLowerCase(Locale.ROOT).equalsIgnoreCase("https")){
                // 检查是否同时开启http/https
                List<String> new_headers = new ArrayList<>();
                for (String header :
                        BurpReqRespTools.getReqHeaders(requestResponse)) {
                    if (!header.contains("Host")){
                        new_headers.add(header);
                    }
                }
                new_headers.add("Host: " + BurpReqRespTools.getHost(requestResponse) + ":80");
                String url = String.format("http://%s%s", BurpReqRespTools.getHost(requestResponse), BurpReqRespTools.getUrlPath(requestResponse));
                // 检测80端口
                okHttpRequester.send(
                    url, 
                    BurpReqRespTools.getMethod(requestResponse), 
                    new_headers, 
                    BurpReqRespTools.getQuery(requestResponse), 
                    new String(BurpReqRespTools.getReqBody(requestResponse)), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new HttpsCallback(this));
            } else if (protocol.toLowerCase(Locale.ROOT).equalsIgnoreCase("http")) {
                // 记录日志
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPathWithQuery(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    Https.class.getSimpleName(),
                    "use http", 
                    null);
            }
            TaskManager.vulsChecked.add(String.format("com.alumm0x.task.config.Https_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
        }
    }
}

class HttpsCallback implements Callback {
    String message = null;
    VulTaskImpl vulTask;

    public HttpsCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        // 记录日志
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, null, vulTask.requestResponse));
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            Https.class.getSimpleName(),
            "onFailure", 
            "[HttpsCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (!response.isRedirect() // 有http自动转https的情况 
            && response.isSuccessful()
            && BurpReqRespTools.getProtocol(requestResponse).equalsIgnoreCase("http")){
            message = "open http";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            Https.class.getSimpleName(),
            message, 
            null);
    }
}