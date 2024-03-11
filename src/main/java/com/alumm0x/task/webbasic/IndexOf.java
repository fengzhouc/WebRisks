package com.alumm0x.task.webbasic;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;


public class IndexOf extends VulTaskImpl {


    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new IndexOf(requestResponse);
    }

    private IndexOf(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        //只检测get请求
        if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("get")){
            //如果就是/，则直接检查响应
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("<title>Index of")) {
                // 记录问题
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPath(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    IndexOf.class.getSimpleName(),
                    "Index of /", 
                    null);
            }else {
                //去掉最后一级path
                String[] q = BurpReqRespTools.getUrlPath(requestResponse).split("/");
                StringBuilder p = new StringBuilder();
                for (int i = 0; i < q.length - 1; i++) {
                    if (!q[i].equalsIgnoreCase("")) {
                        p.append("/").append(q[i]);
                    }
                }
                p.append("/"); //如果没有会自动302，发包器默认不跟进
                String url = BurpReqRespTools.getRootUrl(requestResponse) + p;
                okHttpRequester.send(
                    url, 
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getReqHeaders(requestResponse), 
                    null, 
                    null, 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new IndexOfCallback(this));
            }
        }
    }
}

class IndexOfCallback implements Callback {

    VulTaskImpl vulTask;

    public IndexOfCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        // 记录日志
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, null, vulTask.requestResponse));
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            IndexOf.class.getSimpleName(),
            "onFailure", 
            "[IndexOfCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.isSuccessful()){
            //如果状态码相同则可能存在问题
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("<title>Index of")) {
                message = "发现目录浏览页面";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            IndexOf.class.getSimpleName(),
            message, 
            null);
    }
}