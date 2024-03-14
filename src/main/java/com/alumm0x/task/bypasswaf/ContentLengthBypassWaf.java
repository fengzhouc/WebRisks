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

public class ContentLengthBypassWaf extends VulTaskImpl {
    /*
     * 利用ContentLength
     * 有些中间件会根据Contentlength进行请求解析，会抛弃掉超过contentlength的数据
     * 根据架构，waf一般会在最前面，也就是会在nginx这类中间件的前面，所以payload的后面添加无关的数据用于混淆，然后如果中间件存在解析问题出现截断的情况，则真正的payload就会流到controller
     */

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new ContentLengthBypassWaf(requestResponse);
    }
    private ContentLengthBypassWaf(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add) && BurpReqRespTools.getReqBody(requestResponse).length > 0){
            String reqBody = new String(BurpReqRespTools.getReqBody(requestResponse));
            String str = "qqwertyuiolasdfghjklzxcvbnmsdfasdfasdvasdvasqqwertyuiolasdfghjklzxcvbnmsdfasdfasdvasdvasqqwertyuiolasdfghjklzxcvbnmsdfasdfasdvasdvas";
            // 递增长度到1024
            while (str.length() < 256) {
                str += str;
            }
            List<String> new_headers = new ArrayList<String>();
            //新请求设置length
            for (String header :
                    BurpReqRespTools.getReqHeaders(requestResponse)) {
                // 剔除掉Transfer-Encoding头部
                if (!header.toLowerCase(Locale.ROOT).startsWith("Content-Length".toLowerCase(Locale.ROOT))) {
                    new_headers.add(header);
                }
            }
            // 设置攻击payload的长度
            new_headers.add(String.format("Content-Length:", reqBody.length()));
            okHttpRequester.SendSetContentLength(
                BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                BurpReqRespTools.getMethod(requestResponse), 
                BurpReqRespTools.getReqHeaders(requestResponse), 
                BurpReqRespTools.getQuery(requestResponse), 
                reqBody + str,  // 末尾追加额外的无用数据去混淆，不一定能成功，因为前面payload可能还是会存在攻击特征
                BurpReqRespTools.getContentType(requestResponse), 
                new ContentLengthBypassWafCallback(this));
        }
    }
}

class ContentLengthBypassWafCallback implements Callback {

    VulTaskImpl vulTask;

    public ContentLengthBypassWafCallback(VulTaskImpl vulTask){
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
            ContentLengthBypassWaf.class.getSimpleName(),
            "onFailure", 
            "[ContentLengthBypassWafCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.isSuccessful()){
            message = "确认下是否因为ContentLength截断BypassWaf？";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            ContentLengthBypassWaf.class.getSimpleName(),
            message, 
            null);
    }
}