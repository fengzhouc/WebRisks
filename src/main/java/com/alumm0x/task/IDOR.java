package com.alumm0x.task;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonMess;
import com.alumm0x.util.param.header.HeaderTools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class IDOR extends VulTaskImpl {

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new IDOR(requestResponse);
    }
    private IDOR(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 未授权访问
         * 检测逻辑
         * 1、删除cookie发起请求
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //1、删除cookie，重新发起请求，与原始请求状态码一致则可能存在未授权访问
            // 只测试原本有cookie的请求
            List<String> new_headers = new ArrayList<String>();
            boolean hasCookie = false;
            for (String header :
                    BurpReqRespTools.getReqHeaders(requestResponse)) {
                //删除cookie/authorization头部
                String key = header.split(":")[0];
                if (HeaderTools.isAuth(key.toLowerCase(Locale.ROOT)) // 排除标准认证的头部
                    || !HeaderTools.inNormal(key.toLowerCase(Locale.ROOT))) { // 排除非标准的认证头部
                    hasCookie = true;
                }else {
                    new_headers.add(header);
                }
            }
            // 请求有cookie，进行删除重放
            if (hasCookie){
                //新的请求包
                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                    BurpReqRespTools.getMethod(requestResponse), 
                    new_headers, 
                    BurpReqRespTools.getQuery(requestResponse), 
                    new String(BurpReqRespTools.getReqBody(requestResponse)), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new IDORCallback(this));
            } else { // 没有就说明，天生不带认证的
                // 记录日志
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPathWithQuery(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    IDOR.class.getSimpleName(),
                    "发现未授权访问（默认不带认证凭证）", 
                    null);
            }
        }
    }
}

class IDORCallback implements Callback {

    VulTaskImpl vulTask;

    public IDORCallback(VulTaskImpl vulTask){
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
            IDOR.class.getSimpleName(),
            "onFailure", 
            "[IDORCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.isSuccessful()){
            //如果状态码相同则可能存在问题
            if (BurpReqRespTools.getStatus(requestResponse) == BurpReqRespTools.getStatus(vulTask.requestResponse)
                && Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(vulTask.requestResponse))) {
                message = "发现未授权访问 (删除了会话凭证)";
            }
        } else {
            // 不存在未授权就保存url及cookie信息
            CommonMess.authMessageInfo = vulTask.requestResponse;
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            IDOR.class.getSimpleName(),
            message, 
            null);
    }
}