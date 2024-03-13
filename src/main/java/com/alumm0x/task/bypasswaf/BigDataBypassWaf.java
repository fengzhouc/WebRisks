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

public class BigDataBypassWaf extends VulTaskImpl {
    /*
     * 如果HTTP请求POST BODY太大，检测所有的内容，WAF集群消耗太大的CPU、内存资源。因此许多WAF只检测前面的几K字节、1M、或2M。对于攻击者而然，只需要在POST BODY前面添加许多无用数据，把攻击payload放在最后即可绕过WAF检测
     */

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new BigDataBypassWaf(requestResponse);
    }
    private BigDataBypassWaf(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add) && BurpReqRespTools.getReqBody(requestResponse).length > 0){
            String reqBody = null;
            String str = "qqwertyuiolasdfghjklzxcvbnmsdfasdfasdvasdvasqqwertyuiolasdfghjklzxcvbnmsdfasdfasdvasdvasqqwertyuiolasdfghjklzxcvbnmsdfasdfasdvasdvas";
            // 递增长度到1024
            while (str.length() < 1024) {
                str += str;
            }
            // body前面添加超大数据,有两种数据类型
            if (HttpRequestResponseWithMarkers.indexOf(BurpReqRespTools.getReqBody(requestResponse), "{".getBytes()) != -1) {
                reqBody = String.format("{\"key\"=\"%s\",%s", str , new String(BurpReqRespTools.getReqBody(requestResponse)).substring(1));
            } else if (HttpRequestResponseWithMarkers.indexOf(BurpReqRespTools.getReqBody(requestResponse), "&".getBytes()) != -1) {
                
                reqBody = String.format("key=%s&%s",str, new String(BurpReqRespTools.getReqBody(requestResponse)));
            }

            okHttpRequester.send(
                BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                BurpReqRespTools.getMethod(requestResponse), 
                BurpReqRespTools.getReqHeaders(requestResponse), 
                BurpReqRespTools.getQuery(requestResponse), 
                reqBody, 
                BurpReqRespTools.getContentType(requestResponse), 
                new BigDataBypassWafCallback(this));
        }
    }
}

class BigDataBypassWafCallback implements Callback {

    VulTaskImpl vulTask;

    public BigDataBypassWafCallback(VulTaskImpl vulTask){
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
            BigDataBypassWaf.class.getSimpleName(),
            "onFailure", 
            "[SwaggerApiCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.isSuccessful()){
            message = "BypassWaf 成功";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            BigDataBypassWaf.class.getSimpleName(),
            message, 
            null);
    }
}