package com.alumm0x.task.config;

import burp.*;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import java.util.ArrayList;
import java.util.List;

public class SecureHeader extends VulTaskImpl {

    public static List<String> FIX = new ArrayList<>(); // 安全响应头配置建议
    static {
        FIX.add("Strict-Transport-Securit // max-age=31536000;includeSubDomains;preload");
        FIX.add("X-Frame-Options // allow-from 'url'");
        FIX.add("X-XSS-Protection // 1;mode=block");
        FIX.add("X-Content-Type-Options // nosniff");
        FIX.add("Content-Security-Policy // ");
    }

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SecureHeader(requestResponse);
    }
    private SecureHeader(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            List<String> h = new ArrayList<>();
            if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "X-Frame-Options") == null){
                h.add("X-Frame-Options");
            }
            if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Strict-Transport-Securit") == null){
                h.add("Strict-Transport-Securit");
            }
            if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "X-XSS-Protection") == null){
                h.add("X-XSS-Protection");
            }
            if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "X-Content-Type-Options") == null){
                h.add("X-Content-Type-Options");
            }
            if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Content-Security-Policy") == null){
                h.add("Content-Security-Policy");
            }
            if (h.size() != 0) {
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPath(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    SecureHeader.class.getSimpleName(),
                    "without " + String.join(",", h), 
                    String.join("\n", FIX));
            }
        }
    }
}
