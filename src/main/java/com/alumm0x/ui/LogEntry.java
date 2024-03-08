package com.alumm0x.ui;

import org.jetbrains.annotations.NotNull;

import burp.IHttpRequestResponsePersisted;

//存在漏洞的url信息类
//log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
//                            host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
public class LogEntry implements Comparable
{
    public final int id;
    public  IHttpRequestResponsePersisted requestResponse;
    public  String Host;
    public  String Path;
    public  String Method;
    public  short Status;
    public  String Plugin;
    public  String Risk;
    public  String Desc;


    public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String method, short status, String plugin, String risk, String desc)
    {
        // table tab
        this.id = id;
        this.Host = host;
        this.Path = path;
        this.Method = method;
        this.Status = status;
        this.Plugin = plugin;
        this.Risk = risk;
        // payload tab
        this.Desc = desc;

        this.requestResponse = requestResponse;
    }

    @Override
    public int compareTo(@NotNull Object o) {
        String p = ((LogEntry)o).Path;
        //如果相等则不动
        if (this.Path.equalsIgnoreCase(p)) {
            return -1;
        }
        //其他情况都返回小于的情况
        return -1;
    }
}
