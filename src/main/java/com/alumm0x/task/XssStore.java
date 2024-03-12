package com.alumm0x.task;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.task.collect.FindParamIsId;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.form.FormTools;
import com.alumm0x.util.param.json.JsonTools;

import burp.BurpExtender;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class XssStore extends VulTaskImpl {

    // 记录存在请求参数的请求
    public static List<HttpRequestResponseWithMarkers> note_request_hasParam = new ArrayList<>();
    // 标记当前遍历的请求是否符合要求，每次遍历保存的请求都会初始化
    boolean isFound;
    // 用于验证请求2是否出现flag的条件
    boolean insertFlag = false;
    // 用于flag注入成功后，验证响应是否随之更新
    boolean check = false;
    // 标记此次检测的编号
    String uuid = UUID.randomUUID().toString().substring(0, 8);

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
    @SuppressWarnings("unchecked")
    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)) { 
            // 验证是否flag出现在请求响应体中
            if (check) {
                //新的请求包
                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse),
                    BurpReqRespTools.getReqHeaders(requestResponse),
                    BurpReqRespTools.getQuery(requestResponse),
                    new String(BurpReqRespTools.getReqBody(requestResponse)),
                    BurpReqRespTools.getContentType(requestResponse),
                    new XssStoreCallback(this));
            }  else {
                // 检查请求中是否存在请求参数，包含query、body
                if (BurpReqRespTools.getQuery(requestResponse) != null || BurpReqRespTools.getReqBody(requestResponse).length > 0) {
                    // 如果已经存在了就不添加了
                    if (!note_request_hasParam.contains(requestResponse)) {
                        // 存在请求参数，则保存请求
                        note_request_hasParam.add(requestResponse);
                    }
                }

                // 需要是当前请求有响应body数据的请求才进入检查历史请求参数
                if (BurpReqRespTools.getRespBody(requestResponse).length > 0) {
                    // 遍历保存的请求
                    // 1.找到请求1的用户输入，原样出现在请求2的响应中
                    for (HttpRequestResponseWithMarkers nott_RequestResponseWithMarkers : note_request_hasParam) {
                        // 标记当前遍历的请求是否符合要求，默认都是false
                        isFound = false;
                        String query = null;
                        String req_body = null;
                        // 查询参数
                        if (BurpReqRespTools.getQueryMap(nott_RequestResponseWithMarkers).size() != 0) {
                            FormTools tools = new FormTools();
                            // 遍历保存的请求中的参数值，在当前请求响应中查找匹配
                            tools.formHandler(BurpReqRespTools.getQueryMap(nott_RequestResponseWithMarkers), new ParamHandlerImpl() {
                                @Override
                                public List<ParamKeyValue> handler(Object key, Object value) {
                                    List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                    // 查找是否在当前请求响应中出现保存的请求的参数值(排除空参数值、白名单值、id作用的参数)
                                    if (!"".equals(value.toString()) && !isWithe(value.toString()) && !FindParamIsId.isParamId(key.toString(), value.toString()) && HttpRequestResponseWithMarkers.indexOf(BurpReqRespTools.getRespBody(requestResponse), value.toString().getBytes()) != -1) {
                                        isFound = true;
                                        // 从响应中匹配到了请求参数值，记录一下找到的请求
                                        MainPanel.logAdd(
                                            requestResponse, 
                                            BurpReqRespTools.getHost(requestResponse), 
                                            BurpReqRespTools.getUrlPath(requestResponse),
                                            BurpReqRespTools.getMethod(requestResponse), 
                                            BurpReqRespTools.getStatus(requestResponse), 
                                            XssStore.class.getSimpleName(),
                                            String.format("【%s】三步走-1 当前请求响应体存在历史请求参数值，Query参数：%s=%s", uuid, key, value), 
                                            null);
                                        // 在此请求中出现在响应体的参数添加flag，进行重放验证
                                        paramKeyValues.add(new ParamKeyValue(key, "WebRisks-XssStore"));
                                        return paramKeyValues;
                                    }
                                    paramKeyValues.add(new ParamKeyValue(key, value));
                                    return paramKeyValues;
                                }
                            });
                            // 记录修改后的查询参数
                            query = tools.toString();
                        }
                        // 请求体参数
                        if (new String(BurpReqRespTools.getReqBody(nott_RequestResponseWithMarkers)).startsWith("{")) { // Json对象
                            JsonTools tools = new JsonTools();
                            try {
                                tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(nott_RequestResponseWithMarkers))), new ParamHandlerImpl() {
                                    @Override
                                    public List<ParamKeyValue> handler(Object key, Object value) {
                                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                        // 查找是否在当前请求响应中出现保存的请求的参数值(排除空参数值、白名单值、id作用的参数)
                                        if (!"".equals(value.toString()) && !isWithe(value.toString()) && !FindParamIsId.isParamId(key.toString(), value.toString()) && HttpRequestResponseWithMarkers.indexOf(BurpReqRespTools.getRespBody(requestResponse), value.toString().getBytes()) != -1) {
                                            isFound = true;
                                            // 从响应中匹配到了请求参数值，记录一下找到的请求
                                            MainPanel.logAdd(
                                                requestResponse, 
                                                BurpReqRespTools.getHost(requestResponse), 
                                                BurpReqRespTools.getUrlPath(requestResponse),
                                                BurpReqRespTools.getMethod(requestResponse), 
                                                BurpReqRespTools.getStatus(requestResponse), 
                                                XssStore.class.getSimpleName(),
                                                String.format("【%s】三步走-1 当前请求响应体存在历史请求参数值，Body参数：%s=%s", uuid, key, value), 
                                                null);
                                            // 在此请求中出现在响应体的参数添加flag，进行重放验证
                                            paramKeyValues.add(new ParamKeyValue(key, "WebRisks-XssStore"));
                                            return paramKeyValues;
                                        }
                                        paramKeyValues.add(new ParamKeyValue(key, value));
                                        return paramKeyValues;
                                    }
                                });
                                // 记录修改后的查询参数
                                req_body = tools.toString();
                            } catch (Exception e) {
                                BurpExtender.callbacks.printError("[XssStore.run-Json] " + e.getMessage());
                            }
                        } else if (new String(BurpReqRespTools.getReqBody(nott_RequestResponseWithMarkers)).startsWith("[")) { // Json数组
                            // Json数组的先不处理，常规设计都是Json对象为主，Json数组是嵌在Json对象里面使用的
                        } else { // 其他数据类型，如form表单参数
                            if (BurpReqRespTools.getFormBodyMap(nott_RequestResponseWithMarkers).size() != 0) {
                                isFound = true;
                                FormTools tools = new FormTools();
                                // 遍历保存的请求中的参数值，在当前请求响应中查找匹配
                                tools.formHandler(BurpReqRespTools.getFormBodyMap(nott_RequestResponseWithMarkers), new ParamHandlerImpl() {
                                    @Override
                                    public List<ParamKeyValue> handler(Object key, Object value) {
                                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                        // 查找是否在当前请求响应中出现保存的请求的参数值(排除空参数值、白名单值、id作用的参数)
                                        if (!"".equals(value.toString()) && !isWithe(value.toString()) && !FindParamIsId.isParamId(key.toString(), value.toString()) && HttpRequestResponseWithMarkers.indexOf(BurpReqRespTools.getRespBody(requestResponse), value.toString().getBytes()) != -1) {
                                            // 从响应中匹配到了请求参数值，记录一下找到的请求
                                            MainPanel.logAdd(
                                                requestResponse, 
                                                BurpReqRespTools.getHost(requestResponse), 
                                                BurpReqRespTools.getUrlPath(requestResponse),
                                                BurpReqRespTools.getMethod(requestResponse), 
                                                BurpReqRespTools.getStatus(requestResponse), 
                                                XssStore.class.getSimpleName(),
                                                String.format("【%s】三步走-1 当前请求响应体存在历史请求参数值，Body参数：%s=%s", uuid, key, value), 
                                                null);
                                            // 在此请求中出现在响应体的参数添加flag，进行重放验证
                                            paramKeyValues.add(new ParamKeyValue(key, "WebRisks-XssStore"));
                                            return paramKeyValues;
                                        }
                                        paramKeyValues.add(new ParamKeyValue(key, value));
                                        return paramKeyValues;
                                    }
                                });
                                // 记录修改后的查询参数
                                req_body = tools.toString();
                            }
                        }
                        // 如果找到了，则进行重放验证
                        if (isFound) {
                            //新的请求包
                            okHttpRequester.send(
                                BurpReqRespTools.getUrlWithOutQuery(nott_RequestResponseWithMarkers),
                                BurpReqRespTools.getMethod(nott_RequestResponseWithMarkers),
                                BurpReqRespTools.getReqHeaders(nott_RequestResponseWithMarkers),
                                query,
                                req_body,
                                BurpReqRespTools.getContentType(nott_RequestResponseWithMarkers),
                                new XssStoreCallback(this));
                        }
                    }
                }   
            }
        }
    }

    /** 检查是否例外，比如纯数字、true or false，这些类型的参数值不做比较
     * @param string 参数值
     * @return
     */
    private boolean isWithe(String string) {
        // 检查是否纯数字
        if (isNumeric(string)) {
            return true;
        }
        // 检查是否true or false
        if (string.equalsIgnoreCase("true") || string.equalsIgnoreCase("false")) {
            return true;
        }
        return false;
    }

    /**
     * 判断字符串是否纯数字
     * @param str
     * @return
     */
    public static boolean isNumeric(String str){  
        for (int i = str.length();--i>=0;){    
         if (!Character.isDigit(str.charAt(i))){  
          return false;  
         }  
        }  
        return true;  
      }
}

class XssStoreCallback implements Callback {

    VulTaskImpl vulTask;

    public XssStoreCallback(VulTaskImpl vulTask){
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
            XssStore.class.getSimpleName(),
            "onFailure", 
            "[XssStoreCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        HttpRequestResponseWithMarkers requestResponse = new HttpRequestResponseWithMarkers(BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse));
        if(response.isSuccessful()){
            if (!((XssStore)vulTask).insertFlag) {
                // 重放修改参数成功
                message = String.format("【%s】三步走-2 历史请求参数注入flag成功", ((XssStore)vulTask).uuid);
                // 这里补充对响应进行特征检查，为什么呢？
                // 因为有可能是同一个请求存在xss
                if (HttpRequestResponseWithMarkers.indexOf(BurpReqRespTools.getRespBody(requestResponse), "WebRisks-XssStore".getBytes()) != -1) {
                    message += "，但发现响应中发现注入的flag，疑似存在存储型Xss";
                }
                // 需要重新查看请求2中是否出现flag
                ((XssStore)vulTask).insertFlag = true; // 完成注入，标记一下，这样验证请求2的时候就不会再进入这里了，而是进入下面的esle进行验证响应中是否出现flag
                ((XssStore)vulTask).check = true; // 进行验证，标记一下
                ((XssStore)vulTask).run();
            } else if ( ((XssStore)vulTask).check && HttpRequestResponseWithMarkers.indexOf(BurpReqRespTools.getRespBody(requestResponse), "WebRisks-XssStore".getBytes()) != -1) {
                message = String.format("【%s】三步走-3 响应中发现注入的flag，疑似存在存储型Xss", ((XssStore)vulTask).uuid);
            }
        } else {
            // 会存在请求失败
            // 比如做了参数校验，无法提交成功
            message = String.format("【%s】三步走-2/3 重放失败 ，无法进行后续的XssStore的验证，请求人工确认", ((XssStore)vulTask).uuid);
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
            null);
    }
}