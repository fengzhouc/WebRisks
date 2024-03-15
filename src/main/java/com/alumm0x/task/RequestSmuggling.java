package com.alumm0x.task;

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
import java.util.UUID;

public class RequestSmuggling extends VulTaskImpl {
    /*
     * http请求走私漏洞检测（所谓走私就是中间处理数据时，因为前后端处理不一致，导致有部分数据未被处理，而下一次请求过来的时候，会携带这部分数据，而这部分数据，就可以构造成一个完成的请求）
     * 目前前后端分离的架构，前端与后端如果对请求的解析实现不一致的话，就存在此问题
     * 主要是Content-Length、Transfer-Encoding两个头部，会有如下三种情况
     * 1.前端TE，后端CL：传递完整分块数据，然后Content-Length设置的比body实际要短，这样到后端的时候就会出现截断，末尾的数据就遗留了
     * 2.前端CL，后端TE：传递完整分块数据，但发送的数据包含分块数据+\r\n测试数据，然后Content-Length设置body的实际长度，数据会完整到后端，因为后端使用TE进行解析，那\r\n测试数据这部分数据就遗留了
     * 3.前端TE，后端TE：有两个Transfer-Encoding，前面一个的值异常，后一个值正确，如果解析时取值有差异，比如前端取第一个，后端取第二个，前端因为异常值，会当作普通的请求解析
     * 
     * Reference：
     * https://xz.aliyun.com/t/6299
     * https://portswigger.net/web-security/request-smuggling
     */

     // 标记此次检测的编号
    String uuid = UUID.randomUUID().toString().substring(0, 8);
     // 要支持分块传输才行
     public boolean suportChunked = false;
     // 遗留数据
     public String sugglingData = "sugglingData";
     // 标记第二次请求,第二次请求才会看到遗留的请求信息，一般会拼接在下一个请求的前面
     public boolean secondCheck = false;

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new RequestSmuggling(requestResponse);
    }
    private RequestSmuggling(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add) && BurpReqRespTools.getReqBody(requestResponse).length > 0){
            // 对那些请求进行检测，也不能对所有啊，，而且这个检测都是重放请求，为了避免业务影响是不是可以，所以使用repeater模式，人工挑选一个请求，单独进行吧
            StringBuilder reqBody = new StringBuilder();
            List<String> new_headers = new ArrayList<String>();
            //新请求增加Transfer-Encoding
            for (String header :
                    BurpReqRespTools.getReqHeaders(requestResponse)) {
                // 剔除掉Transfer-Encoding, Content-Type头部
                if (!header.toLowerCase(Locale.ROOT).startsWith("Transfer-Encoding".toLowerCase(Locale.ROOT))
                    || !header.toLowerCase(Locale.ROOT).startsWith("Content-Type".toLowerCase(Locale.ROOT))) {
                    new_headers.add(header);
                }
            }
            // 将数据进行分块格式化
            String req = new String(BurpReqRespTools.getReqBody(requestResponse));
            // 全部按长度1
            for (int i = 0; i < req.length(); ++i){    
                reqBody.append(String.format("1\r\n%s\r\n", req.charAt(i))); 
            } 
            // 检测是否支持分块传输
            if (!suportChunked) {
                // 添加分块数据结束
                reqBody.append("0\r\n\r\n"); // 标记结束
                // 添加TE头部
                new_headers.add("Transfer-Encoding:chunked");
                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                    BurpReqRespTools.getMethod(requestResponse), 
                    new_headers, 
                    BurpReqRespTools.getQuery(requestResponse), 
                    reqBody.toString(), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new RequestSmugglingCallback(this, null));
            } else if (suportChunked) { // 第一次请求跟第二次请求都发送一起的请求
                // TE CL情况
                tecl(requestResponse, new_headers, reqBody);
                // CL TE情况
                clte(requestResponse, new_headers, reqBody);
                // TE TE情况
                tete(requestResponse, new_headers, reqBody);
            }
            
        }
    }

    /**
     * 1.前端TE，后端CL：传递完整分块数据，然后Content-Length设置的比body实际要短，这样到后端的时候就会出现截断，末尾的数据就遗留了
     * @param requestResponse
     * @param headers
     * @param reqBody
     */
    private void tecl(HttpRequestResponseWithMarkers requestResponse, List<String> headers, StringBuilder reqBody) {
        List<String> new_headers = new ArrayList<String>();
            // 剔除掉CL
            for (String header : headers) {
                // 剔除掉Transfer-Encoding头部
                if (!header.toLowerCase(Locale.ROOT).startsWith("Content-Lengths".toLowerCase(Locale.ROOT))) {
                    new_headers.add(header);
                }
            }
        // 计算添加遗留数据前的长度
        int cl = reqBody.toString().length();
        // 添加遗留数据到分块数据中
        reqBody.append(String.format("%d\r\n%s\r\n", sugglingData.length(), sugglingData)); 
        // 添加分块数据结束
        reqBody.append("0\r\n\r\n"); // 标记结束
        // 添加TE头部
        new_headers.add("Transfer-Encoding:chunked");
        // 添加CL头，CL的值比实际body的要短
        new_headers.add(String.format("Content-Lengths: %d", cl));
        // 使用不更新CL的方式进行发送请求
        okHttpRequester.SendSetContentLength(
            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
            BurpReqRespTools.getMethod(requestResponse), 
            new_headers, 
            BurpReqRespTools.getQuery(requestResponse), 
            reqBody.toString(), 
            BurpReqRespTools.getContentType(requestResponse), 
            new RequestSmugglingCallback(this, "TE.CL"));
    }

    /**
     * 2.前端CL，后端TE：传递完整分块数据，但发送的数据包含分块数据+\r\n测试数据，然后Content-Length设置body的实际长度，数据会完整到后端，因为后端使用TE进行解析，那\r\n测试数据这部分数据就遗留了
     * @param requestResponse
     * @param headers
     * @param reqBody
     */
    private void clte(HttpRequestResponseWithMarkers requestResponse, List<String> headers, StringBuilder reqBody) {
        List<String> new_headers = new ArrayList<String>();
            // 剔除掉CL
            for (String header : headers) {
                // 剔除掉Transfer-Encoding头部
                if (!header.toLowerCase(Locale.ROOT).startsWith("Content-Lengths".toLowerCase(Locale.ROOT))) {
                    new_headers.add(header);
                }
            }
        // 添加分块数据结束
        reqBody.append("0\r\n\r\n"); // 标记结束
        // 添加遗留数据到分块数据中
        reqBody.append(String.format("\r\n%s\r\n", sugglingData)); 
        // 计算添加遗留数据前的长度
        int cl = reqBody.toString().length();
        // 添加TE头部
        new_headers.add("Transfer-Encoding:chunked");
        // 添加CL头，CL的值比实际body的要短
        new_headers.add(String.format("Content-Lengths: %d", cl));
        // 使用不更新CL的方式进行发送请求
        okHttpRequester.SendSetContentLength(
            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
            BurpReqRespTools.getMethod(requestResponse), 
            new_headers, 
            BurpReqRespTools.getQuery(requestResponse), 
            reqBody.toString(), 
            BurpReqRespTools.getContentType(requestResponse), 
            new RequestSmugglingCallback(this, "CL.TE"));
    }

    /**
     * 3.前端TE，后端TE：有两个Transfer-Encoding，前面一个的值异常，后一个值正确，如果解析时取值有差异，比如前端取第一个，后端取第二个，前端因为异常值，会当作普通的请求解析
     * @param requestResponse
     * @param headers
     * @param reqBody
     */
    private void tete(HttpRequestResponseWithMarkers requestResponse, List<String> headers, StringBuilder reqBody) {
        // 添加TE头部
        headers.add("Transfer-Encoding:chunkedxxx"); // 如果前端识别第一个异常后，当作普通请求进行解析
        headers.add("Transfer-Encoding:chunked");
        // 添加分块数据结束
        reqBody.append("0\r\n\r\n"); // 标记结束
        // 添加遗留数据到分块数据中
        reqBody.append(String.format("\r\n%s\r\n", sugglingData)); 
        // 使用不更新CL的方式进行发送请求
        okHttpRequester.defSend(
            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
            BurpReqRespTools.getMethod(requestResponse), 
            headers, 
            BurpReqRespTools.getQuery(requestResponse), 
            reqBody.toString(), 
            BurpReqRespTools.getContentType(requestResponse), 
            new RequestSmugglingCallback(this, "TE.TE"));
    }
}

class RequestSmugglingCallback implements Callback {

    VulTaskImpl vulTask;
    String type; // 表示类型：TE.CL、CL.TE、TE.TE

    public RequestSmugglingCallback(VulTaskImpl vulTask, String type){
        this.vulTask = vulTask;
        this.type = type;
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
            RequestSmuggling.class.getSimpleName(),
            "onFailure", 
            "[RequestSmugglingCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.isSuccessful() && !((RequestSmuggling)vulTask).suportChunked){
            message = String.format("【%s】1.支持HTTP分块传输", ((RequestSmuggling)vulTask).uuid);
            ((RequestSmuggling)vulTask).suportChunked = true;
            ((RequestSmuggling)vulTask).run();
        } else if (((RequestSmuggling)vulTask).suportChunked
                && ((RequestSmuggling)vulTask).secondCheck) { // 第二次请求的验证
            // 第二次请求才会看到遗留的请求信息，一般会拼接在下一个请求的前面，所以常规出现的应该是请求失败
            if (!response.isSuccessful()) {
                switch (this.type) {
                    case "TE.CL":
                        message = String.format("【%s】【%s】3.第二次请求成功, 并且出现异常", ((RequestSmuggling)vulTask).uuid, type);
                        break;
                        case "CL.TE":
                        message = String.format("【%s】【%s】3.第一次请求成功, 并且出现异常", ((RequestSmuggling)vulTask).uuid, type);
                        break;
                        case "TE.TE":
                        message = String.format("【%s】【%s】3.第一次请求成功, 并且出现异常", ((RequestSmuggling)vulTask).uuid, type);
                        break;
                    default:
                        break;
                }
            }
            // 第一次请求成功
        } else if (response.isSuccessful() && ((RequestSmuggling)vulTask).suportChunked) {
            switch (this.type) {
                case "TE.CL":
                    message = String.format("【%s】【%s】2.第一次请求成功", ((RequestSmuggling)vulTask).uuid, type);
                    break;
                    case "CL.TE":
                    message = String.format("【%s】【%s】2.第一次请求成功", ((RequestSmuggling)vulTask).uuid, type);
                    break;
                    case "TE.TE":
                    message = String.format("【%s】【%s】2.第一次请求成功", ((RequestSmuggling)vulTask).uuid, type);
                    break;
                default:
                    break;
            }
            // 进行第二次请求验证是否存在走私问题
            ((RequestSmuggling)vulTask).secondCheck = true;
            ((RequestSmuggling)vulTask).run();
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            RequestSmuggling.class.getSimpleName(),
            message, 
            null);
    }
}