package com.alumm0x.task;

import java.io.IOException;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.ToolsUtil;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class XssStore extends VulTaskImpl {

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new XssStore(requestResponse);
    }

    private XssStore(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    /**
     * 存储型Xss检测
     * 检测原理：
     * 1.找到请求1的用户输入，原样出现在请求2的响应中
     * 2.修改请求1的用户输入（带有一定的xsspayload）进行重放，再重复请求2查看响应中是否包含xsspayload
     *  - 请求1，即xss人口
     *  - 请求2，即xss的回显（这里存在个问题：并不一定会在html中展示，可能纯粹就是接口返回），如何确定是否真实存在？
     *     - 只要找到会跟随请求1用户输入变化而响应对应变化的请求2即可（排除所有静态资源，不包含js）
     *       思考过程：
     *          - 人工确认，这个下下策，发现疑似的，则人工确认下，怎么确认？
     *              - 访问请求2的Referer的url（这个Referer的url大概率就是当前页面的url），查看页面源码是是否存在xsspayload
     *          - 看下请求2是否html页面呢？，如果是页面则大概率存在，人工刷新页面再确认下（这只是覆盖了很传统的应用框架的情况）
     *              - 目前的应用架构，基本都是前后端分离，也就是说页面是模版页面，数据通过后端接口返回后再做渲染展示
     *              - 这种架构下，只能确认到请求1的的用户输入，在请求2的响应中找到，然后人工确认
     *              - 检测哪些类型的请求呢，肯定不只是html了，常规存储型Xss数据还是存储在数据库的，所以限定在后端接口的类型，此外包含js，比如jsonp的情况会携带后端的数据回前端
     *          - 请求1跟请求2不一定是不一样的，也有可能是同一个请求，所以检测的时候不需要在意是否第二个请求，对原请求也进行响应检测
     * 3.人工确认：访问请求2的Referer的url，也就是页面rootUrl，然后查看页面源码是否包含xsspayload，再深度构造xsspayload进行验证    
     */
    @Override
    public void run() {
        
    }
    
}

class XssStoreCallback implements Callback {

    VulTaskImpl vulTask;
    String xssString = null;

    public XssStoreCallback(VulTaskImpl vulTask, String xssString){
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
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            XssStore.class.getSimpleName(),
            "onFailure", 
            "[XssStoreCallback-onFailure] " + e.getMessage());
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
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            XssStore.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/XssReflect.bbm")));
    }
}