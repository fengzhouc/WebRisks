package com.alumm0x.task.collect;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;


public class WeChatSessionKey extends VulTaskImpl {

    /*
     * 微信SessionKey泄漏,会造成任意用户登陆;
     * 禁止返回SessionKey到客户端,造成泄漏风险.;
     */

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new WeChatSessionKey(requestResponse);
    }
    private WeChatSessionKey(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        String message = null;
        // 检查响应中是否包含sessionkek关键字
        String body = new String(BurpReqRespTools.getRespBody(requestResponse));
        if (body.toLowerCase().contains("sessionkey") || body.toLowerCase().contains("session_key") || body.toLowerCase().contains("session-key")) {
            message = "has WeChat SessionKey";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            WeChatSessionKey.class.getSimpleName(),
            message, 
            null);
    }
}

