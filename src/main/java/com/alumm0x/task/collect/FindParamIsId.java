package com.alumm0x.task.collect;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.task.XssStore;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.form.FormTools;
import com.alumm0x.util.param.json.JsonTools;

import burp.BurpExtender;

public class FindParamIsId extends VulTaskImpl {

    // 标记此次检测的编号
    String uuid = UUID.randomUUID().toString().substring(0, 8);

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new FindParamIsId(requestResponse);
    }
    private FindParamIsId(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void run() {
        /**
         * 遍历所有请求参数，检测是否疑似id作用的参数
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), new ArrayList<>())){
            // 需要是当前请求有响应body数据的请求才进入检查历史请求参数
            if (BurpReqRespTools.getRespBody(requestResponse).length > 0) {
                // 遍历请求的参数
                // 查询参数
                if (BurpReqRespTools.getQueryMap(requestResponse).size() != 0) {
                    FormTools tools = new FormTools();
                    // 遍历保存的请求中的参数值
                    tools.formHandler(BurpReqRespTools.getQueryMap(requestResponse), new ParamHandlerImpl() {
                        @Override
                        public List<ParamKeyValue> handler(Object key, Object value) {
                            List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                            // 查看是否疑似ID的参数
                            if (value != null && isParamId(key.toString(), value.toString())) {
                                // 从响应中匹配到了请求参数值，记录一下找到的请求
                                MainPanel.logAdd(
                                    requestResponse, 
                                    BurpReqRespTools.getHost(requestResponse), 
                                    BurpReqRespTools.getUrlPath(requestResponse),
                                    BurpReqRespTools.getMethod(requestResponse), 
                                    BurpReqRespTools.getStatus(requestResponse), 
                                    FindParamIsId.class.getSimpleName(),
                                    String.format("【%s】疑似Id作用的请求参数，Query参数：%s=%s", uuid, key, value), 
                                    null);
                            }
                            paramKeyValues.add(new ParamKeyValue(key, value));
                            return paramKeyValues;
                        }
                    });
                }
                // 请求体参数
                if (new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("{")) { // Json对象
                    JsonTools tools = new JsonTools();
                    try {
                        tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(requestResponse))), new ParamHandlerImpl() {
                            @Override
                            public List<ParamKeyValue> handler(Object key, Object value) {
                                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                // 查看是否疑似ID的参数
                                if (value != null && isParamId(key.toString(), value.toString())) {
                                    // 从响应中匹配到了请求参数值，记录一下找到的请求
                                    MainPanel.logAdd(
                                        requestResponse, 
                                        BurpReqRespTools.getHost(requestResponse), 
                                        BurpReqRespTools.getUrlPath(requestResponse),
                                        BurpReqRespTools.getMethod(requestResponse), 
                                        BurpReqRespTools.getStatus(requestResponse), 
                                        FindParamIsId.class.getSimpleName(),
                                        String.format("【%s】疑似Id作用的请求参数，Body参数：%s=%s", uuid, key, value), 
                                        null);
                                }
                                paramKeyValues.add(new ParamKeyValue(key, value));
                                return paramKeyValues;
                            }
                        });
                    } catch (Exception e) {
                        BurpExtender.callbacks.printError("[FindParamIsId.run-Json] " + e.getMessage());
                    }
                } else if (new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("[")) { // Json数组
                    // Json数组的先不处理，常规设计都是Json对象为主，Json数组是嵌在Json对象里面使用的
                } else { // 其他数据类型，如form表单参数
                    if (BurpReqRespTools.getFormBodyMap(requestResponse).size() != 0) {
                        FormTools tools = new FormTools();
                        // 遍历保存的请求中的参数值
                        tools.formHandler(BurpReqRespTools.getFormBodyMap(requestResponse), new ParamHandlerImpl() {
                            @Override
                            public List<ParamKeyValue> handler(Object key, Object value) {
                                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                // 查找是否在当前请求响应中出现保存的请求的参数值
                                if (value != null && isParamId(key.toString(), value.toString())) {
                                    // 从响应中匹配到了请求参数值，记录一下找到的请求
                                    MainPanel.logAdd(
                                        requestResponse, 
                                        BurpReqRespTools.getHost(requestResponse), 
                                        BurpReqRespTools.getUrlPath(requestResponse),
                                        BurpReqRespTools.getMethod(requestResponse), 
                                        BurpReqRespTools.getStatus(requestResponse), 
                                        FindParamIsId.class.getSimpleName(),
                                        String.format("【%s】疑似Id作用的请求参数，Body参数：%s=%s", uuid, key, value), 
                                        null);
                                }
                                paramKeyValues.add(new ParamKeyValue(key, value));
                                return paramKeyValues;
                            }
                        });
                    }
                }
            }
            // 检查响应体中的ID数据
            if (BurpReqRespTools.getRespBody(requestResponse).length > 0) {
                // 主要覆盖响应返回json对象的情况
                if (new String(BurpReqRespTools.getRespBody(requestResponse)).startsWith("{")) { // Json对象
                    JsonTools tools = new JsonTools();
                    List<String> ids = new ArrayList<>();
                    try {
                        tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getRespBody(requestResponse))), new ParamHandlerImpl() {
                            @Override
                            public List<ParamKeyValue> handler(Object key, Object value) {
                                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                // 查看是否疑似ID的参数
                                if (value != null && isParamId(key.toString(), value.toString())) {
                                    // 从响应中匹配到了请求参数值，记录一下找到的请求
                                    MainPanel.logAdd(
                                        requestResponse, 
                                        BurpReqRespTools.getHost(requestResponse), 
                                        BurpReqRespTools.getUrlPath(requestResponse),
                                        BurpReqRespTools.getMethod(requestResponse), 
                                        BurpReqRespTools.getStatus(requestResponse), 
                                        FindParamIsId.class.getSimpleName(),
                                        String.format("【%s】疑似Id作用的响应内容，RespBody字段：%s=%s", uuid, key, value), 
                                        null);
                                    // 提取id数据,响应中可能会存在大量的id数据，提取出来可以用
                                    ids.add(String.format("%s=%s", key, value));
                                }
                                paramKeyValues.add(new ParamKeyValue(key, value));
                                return paramKeyValues;
                            }
                        });
                    } catch (Exception e) {
                        BurpExtender.callbacks.printError("[FindParamIsId.run-Json] " + e.getMessage());
                    }
                    if (ids.size() > 0) {
                        // 将List转换为Set，自动去除重复元素
                        Set<String> set = new HashSet<>(ids);
                        // 再次将Set转换为List，得到去重后的结果
                        List<String> distinctNumbers = new ArrayList<>(set);
                        // 排序
                        Collections.sort(distinctNumbers);
                        MainPanel.logAdd(
                            requestResponse, 
                            BurpReqRespTools.getHost(requestResponse), 
                            BurpReqRespTools.getUrlPath(requestResponse),
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getStatus(requestResponse), 
                            FindParamIsId.class.getSimpleName(),
                            String.format("【%s】疑似Id作用的响应内容，已提取数据，详细请查看“Found & Fix”", uuid), 
                            String.join("\n", distinctNumbers));
                    }
                }
            }
        }
    }

    /**
     * 检查参数是否Id作用的
     * @param key 参数名
     * @param value 参数值
     * @return boolean
     */
    public static boolean isParamId(String key, String value) {
        // 1. 参数名带有id字样的结尾，常见都是Id结尾
        if (key.toLowerCase().endsWith("id")) {
            return true;
        } else if (isUUID(value)) {  // 2. 判断参数值是否uuid
            return true;
        } else if (XssStore.isNumeric(value) && value.length() > 6 && !isTimesmap(value)) {
            // 3. 纯数字的情况 (包含了雪花算法ID的情况),注意，这里排除了时间戳的情况
            //  value.length() > 6 排除掉页码的情况
            //  !isTimesmap(value) 排除掉时间戳的情况
            return true;
        }
        return false;
    }

    /**
     * 检测是否uuid，常见使用的一种
     * @param uuid
     * @return
     */
    private static boolean isUUID(String uuid) {
        String regex = "^([a-fA-F0-9]{8}[-]*?[a-fA-F0-9]{4}[-]*?[a-fA-F0-9]{4}[-]*?[a-fA-F0-9]{4}[-]*?[a-fA-F0-9]{12})$";
        return uuid.matches(regex);
    }

    /**
     * 判断是否时间戳
     * @param time
     * @return
     */
    private static boolean isTimesmap(String time) {
        try {
            Instant.ofEpochSecond(Long.parseLong(time));
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
