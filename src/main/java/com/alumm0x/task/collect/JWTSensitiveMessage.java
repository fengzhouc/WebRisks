package com.alumm0x.task.collect;

import burp.BurpExtender;
import burp.IParameter;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.json.JsonTools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;


public class JWTSensitiveMessage extends VulTaskImpl {

    String message = null;
    String jwt_decode = ""; // 记录jwt即解码后的数据
    /*
     * JWT敏感信息检测。是否在JWT中传输敏感信息，这里主要检测账号密码/token。";
     */

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new JWTSensitiveMessage(requestResponse);
    }
    private JWTSensitiveMessage(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void run() {
        List<String> suffix = new ArrayList<>();
        suffix.add(".js");
        // 后缀检查，静态资源不做测试
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), suffix)){
            // 检查请求的参数，使用burp解析的，包含如下:查询参数/cookie/form参数
            for (IParameter parameter : BurpExtender.helpers.analyzeRequest(requestResponse).getParameters()) {
                byte[] decode = BurpExtender.helpers.base64Decode(parameter.getValue());
                if (new String(decode).contains("\"alg\"") && isSensitiveKey(new String(decode))) {
                    message = "参数:JWT中存在敏感信息";
                    // 记录jwt的信息
                    jwt_decode += String.format("## Parameter(%s):found the JWT\n", parameter.getName());
                    jwt_decode += parameter.getValue();
                    jwt_decode += "\n## Decode\n";
                    jwt_decode += new String(decode);
                    jwt_decode += "\n\n";
                }
            }
            // 检查请求头
            for (Entry<String, Object> item : BurpReqRespTools.getReqHeadersToMap(requestResponse).entrySet()) {
                String value = item.getValue().toString();
                // JWT会用在Authorization头部，但是这个头部的value前面会带一个认证类型，空格隔，后面的才是真实的value，这里做一下处理
                if (item.getKey().equalsIgnoreCase("Authorization")) {
                    value = value.split("\\s+", 2)[1];
                }
                byte[] decode = BurpExtender.helpers.base64Decode(value);
                if (new String(decode).contains("\"alg\"") && isSensitiveKey(new String(decode))) {
                    message = "请求头:JWT中存在敏感信息";
                    // 记录jwt的信息
                    jwt_decode += String.format("## ReqHeader(%s):found the JWT\n", item.getKey());
                    jwt_decode += value;
                    jwt_decode += "\n## Decode\n";
                    jwt_decode += new String(decode);
                    jwt_decode += "\n\n";
                }
            }
            // 检查json数据
            if (BurpReqRespTools.getReqBody(requestResponse).length > 0
                && new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("{")){
                JsonTools tools = new JsonTools();
                try {
                    tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(requestResponse))), new ParamHandlerImpl() {
                        @Override
                        public List<ParamKeyValue> handler(Object key, Object value) {
                            List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                            byte[] decode = BurpExtender.helpers.base64Decode(value.toString());
                            if (new String(decode).contains("\"alg\"") && isSensitiveKey(new String(decode))) {
                                message = "Json参数:JWT中存在敏感信息";
                                // 记录jwt的信息
                                jwt_decode += String.format("## Json Parameter(%s):found the JWT\n", key);
                                jwt_decode += value.toString();
                                jwt_decode += "\n## Decode\n";
                                jwt_decode += new String(decode);
                                jwt_decode += "\n\n";
                            }
                            paramKeyValues.add(new ParamKeyValue(key, value));
                            return paramKeyValues;
                        }
                    });
                } catch (Exception e) {
                    BurpExtender.callbacks.printError("[JWTSensitiveMessage.run] " + e.getMessage());
                }
            }
            if (message != null) {
                // 记录日志
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPath(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    JWTSensitiveMessage.class.getSimpleName(),
                    message, 
                    jwt_decode);   
            }
        }
    }

    /**
     * 判断是否敏感信息的key
     * @param key
     * @return
     */
    public boolean isSensitiveKey(String key){
        if (key.contains("password")
                || key.contains("token")
                || key.contains("phone")) {
            return true;
        }
        return false;
    }
}
