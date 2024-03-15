package com.alumm0x.task.api;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;


public class FindSensitiveApi extends VulTaskImpl {

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new FindSensitiveApi(requestResponse);
    }
    private FindSensitiveApi(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {

        //遍历所有指纹，进行请求验证
        for (String url_banner : SourceLoader.loadSources("/banner/banners_url.oh")) {
            String[] banner =url_banner.split(",",2);
            String url =BurpReqRespTools.getRootUrl(requestResponse) + banner[0];
            //新的请求包
            okHttpRequester.send(
                url, 
                "GET", 
                BurpReqRespTools.getReqHeaders(requestResponse), 
                null, 
                null, 
                BurpReqRespTools.getContentType(requestResponse), 
                new FindSensitiveApiCallback(this, banner[1]));
        }
        TaskManager.vulsChecked.add(String.format("com.alumm0x.task.api.FindSensitiveApi_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
    }
}

class FindSensitiveApiCallback implements Callback {
    VulTaskImpl vulTask;
    String tip;

    public FindSensitiveApiCallback(VulTaskImpl vulTask, String tip){
        this.vulTask = vulTask;
        this.tip = tip;
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
            FindSensitiveApi.class.getSimpleName(),
            "onFailure", 
            "[FindSensitiveApiCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.code() != 404 // 排除不存在
            && response.code() != 400 // 排除客户端错误
            && response.code() / 10 != 50){ // 排除50x服务端错误
            // 状态码不存在则认为存在该API
            message = this.tip;
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            FindSensitiveApi.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSourcesWithNote("/banner/banners_url.oh")));
    }
}