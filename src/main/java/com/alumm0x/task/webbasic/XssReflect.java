package com.alumm0x.task.webbasic;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.ToolsUtil;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.form.FormTools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class XssReflect extends VulTaskImpl {

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new XssReflect(requestResponse);
    }
    private XssReflect(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特使flag
         * 2、然后检查响应头是否存在flag
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //反射型只测查询参数
            String querystring = BurpReqRespTools.getQuery(requestResponse);
            if (querystring == null) {
                // 没有查询参数的话，插入一个试试，为啥这个搞呢，有些会把url潜入到页面中，比如错误信息的时候，所以这时如果没有防护，那基本就存在问题的
                querystring = "test=test";
            }
            // 加载payload的模版
            List<String> payloads = SourceLoader.loadSources("/payloads/ReflectXss.bbm");
            for (String paylaod : payloads) {
                FormTools tools = new FormTools();
                tools.formHandler(BurpReqRespTools.getQueryMap(requestResponse), new ParamHandlerImpl() {
                    @Override
                    public List<ParamKeyValue> handler(Object key, Object value) {
                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                        paramKeyValues.add(new ParamKeyValue(key, BurpExtender.helpers.urlEncode(paylaod)));
                        return paramKeyValues;
                    }
                });
                //新的请求包
                okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse),
                    BurpReqRespTools.getReqHeaders(requestResponse),
                    tools.toString(),
                    new String(BurpReqRespTools.getReqBody(requestResponse)),
                    BurpReqRespTools.getContentType(requestResponse),
                    new XssReflectCallback(this, paylaod));
            }
        }
    }
}

class XssReflectCallback implements Callback {

    VulTaskImpl vulTask;
    String xssString = null;

    public XssReflectCallback(VulTaskImpl vulTask, String xssString){
        this.vulTask = vulTask;
        this.xssString = xssString;
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
            XssReflect.class.getSimpleName(),
            "onFailure", 
            "[XssReflectCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        String ct = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Content-Type");
        // 反射性仅存在于响应content-type是页面等会被浏览器渲染的资源，比如json响应是没有的，有也是dom型
        if(ct != null && (
            ct.contains("text/html") 
            || ct.contains("application/xhtml+xml")
            || ct.contains("application/x-www-form-urlencoded")
            || ct.contains("image/svg+xml")
            )){
            //检查验证数据是否原样在响应中出现
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains(this.xssString)) {
                message = "发现疑似反射型XSS（响应中检测到无编码处理的payload）";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            XssReflect.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/XssReflect.bbm")));
    }
}