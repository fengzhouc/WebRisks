package com.alumm0x.task;

import burp.BurpExtender;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.LogEntry;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.TimeUnit;

public class Ssrf extends VulTaskImpl {

    String OriginDM = ""; // 记录原domain
    public boolean dnslog = false;
    public IBurpCollaboratorClientContext collaboratorClientContext;
    public LogEntry entry; // 因为需要刷新dnslog的记录，所以保存log，可以进行数据更新

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Ssrf(requestResponse);
    }
    private Ssrf(IHttpRequestResponse requestResponse) {
        super(requestResponse);
        this.entry =MainPanel.logAdd(
                        requestResponse, 
                        BurpReqRespTools.getHost(requestResponse), 
                        BurpReqRespTools.getUrlPath(requestResponse),
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getStatus(requestResponse), 
                        Ssrf.class.getSimpleName(),
                        "Ssrf Checking", 
                        String.join("\n", SourceLoader.loadSources("/payloads/SsrfRegex.bbm")));
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
            String payload = collaboratorClientContext.generatePayload(true);
            String regex = "http[s]?://(.*?)[/&\"]+?\\w*?"; //分组获取域名
            String evilHost = "evil6666.com";
            String query = BurpReqRespTools.getQuery(requestResponse);
            String request_body_str = new String(BurpReqRespTools.getReqBody(requestResponse));
            //如果有body参数，需要对body参数进行测试
            if (request_body_str.length() > 0){
                //1.先检测是否存在url地址的参数，正则匹配
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(request_body_str);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String domain = matcher.group(1);
                    OriginDM = domain;
                    // 修改为别的域名
                    String req_body = dnslog ? new String(BurpReqRespTools.getReqBody(requestResponse)).replace(domain, payload) : new String(BurpReqRespTools.getReqBody(requestResponse)).replace(domain, evilHost);
                    //新的请求包
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getReqHeaders(requestResponse), 
                        BurpReqRespTools.getQuery(requestResponse), 
                        req_body, 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new SsrfCallback(this, entry));
                }
            }else if (query != null){
                //1.先检测是否存在url地址的参数，正则匹配
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(query);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String domain = matcher.group(1);
                    OriginDM = domain;
                    // callbacks.printOutput(domain);
                    // 修改为别的域名
                    String req_query = dnslog ? BurpReqRespTools.getQuery(requestResponse).replace(domain, payload) : BurpReqRespTools.getQuery(requestResponse).replace(domain, evilHost);
                    //新的请求包
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getReqHeaders(requestResponse), 
                        req_query, 
                        new String(BurpReqRespTools.getReqBody(requestResponse)), 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new SsrfCallback(this, entry));
                }
            }
        }
    }

}

class SsrfCallback implements Callback {

    VulTaskImpl vulTask;
    LogEntry entry;

    public SsrfCallback(VulTaskImpl vulTask, LogEntry entry){
        this.vulTask = vulTask;
        this.entry = entry;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        // 记录日志
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, null, vulTask.requestResponse);
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            Ssrf.class.getSimpleName(),
            "onFailure", 
            "[SsrfCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (((Ssrf)vulTask).dnslog) {
            entry.Risk += ",try DnsLog ";
            try {
                TimeUnit.SECONDS.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            List<IBurpCollaboratorInteraction> ret = ((Ssrf) vulTask).collaboratorClientContext.fetchAllCollaboratorInteractions();
            if (ret.size() > 0){
                for (IBurpCollaboratorInteraction i :
                        ret) {
                    entry.Risk += i;
                }
            }
            // 更新table中的数据
            refreshEntry(requestResponse);
        } else {
            // 检查响应中是否存在flag
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("evil6666.com")) {
                entry.Risk = "SSRF, in Resp, OriginDM: "+ ((Ssrf)vulTask).OriginDM;
                tryDnslog();
            }else if (response.isSuccessful()){
                // 可能响应并没有回馈，所以这时响应是成功的也告警
                entry.Risk  = "SSRF, Not in Resp, OriginDM: "+ ((Ssrf)vulTask).OriginDM;
                tryDnslog();
            }
        }
    }
        
    /**
     * 尝试dnslog，验证ssrf
     */
    private void tryDnslog(){
        ((Ssrf)vulTask).dnslog = true;
        ((Ssrf)vulTask).run();
    }

    private void refreshEntry(IHttpRequestResponse requestResponse) {
        entry.requestResponse = BurpExtender.callbacks.saveBuffersToTempFiles(requestResponse);
        entry.Host = BurpReqRespTools.getHost(requestResponse);
        entry.Path = BurpReqRespTools.getUrlPath(requestResponse);
        entry.Method = BurpReqRespTools.getMethod(requestResponse);
        entry.Status = BurpReqRespTools.getStatus(requestResponse);
    }
}