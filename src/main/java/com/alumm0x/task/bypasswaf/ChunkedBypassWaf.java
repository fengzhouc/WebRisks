package com.alumm0x.task.bypasswaf;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ChunkedBypassWaf extends VulTaskImpl {
    /*
     * 利用http的分块传输
     * 1.设置Transfer-Encoding:chunked
     * 2.数据格式
     * 长度\r\n数据\r\n
     * 长度\r\n数据\r\n
     * 长度\r\n数据\r\n
     * \r\n 结束
     */

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new ChunkedBypassWaf(requestResponse);
    }
    private ChunkedBypassWaf(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add) && BurpReqRespTools.getReqBody(requestResponse).length > 0){
            StringBuilder reqBody = new StringBuilder();
            List<String> new_headers = new ArrayList<String>();
            //新请求增加Transfer-Encoding
            for (String header :
                    BurpReqRespTools.getReqHeaders(requestResponse)) {
                // 剔除掉Transfer-Encoding头部
                if (!header.toLowerCase(Locale.ROOT).startsWith("Transfer-Encoding".toLowerCase(Locale.ROOT))) {
                    new_headers.add(header);
                }
            }
            new_headers.add("Transfer-Encoding:chunked");
            // 将数据进行分块格式化
            String req = new String(BurpReqRespTools.getReqBody(requestResponse));
            // 全部按长度1
            for (int i = 0; i < req.length(); ++i){    
                reqBody.append(String.format("1\r\n%s\r\n", req.charAt(i))); 
            } 
            reqBody.append("0\r\n\r\n"); // 标记结束
            okHttpRequester.send(
                BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                BurpReqRespTools.getMethod(requestResponse), 
                BurpReqRespTools.getReqHeaders(requestResponse), 
                BurpReqRespTools.getQuery(requestResponse), 
                reqBody.toString(), 
                BurpReqRespTools.getContentType(requestResponse), 
                new ChunkedBypassWafCallback(this));
        }
    }
}

class ChunkedBypassWafCallback implements Callback {

    VulTaskImpl vulTask;

    public ChunkedBypassWafCallback(VulTaskImpl vulTask){
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
            ChunkedBypassWaf.class.getSimpleName(),
            "onFailure", 
            "[ChunkedBypassWafCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.isSuccessful()){
            message = "确认下是否使用Http分块传输成功BypassWaf？";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            ChunkedBypassWaf.class.getSimpleName(),
            message, 
            null);
    }
}