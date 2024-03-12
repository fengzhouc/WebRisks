package com.alumm0x.util.param.json;

import java.util.*;

import org.json.JSONArray;
import org.json.JSONObject;

import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;

import burp.BurpExtender;

public class JsonTools {

    // 保存篡改的json串
    public final StringBuilder stringBuilder;

    public String toString(){
        return stringBuilder.toString();
    }

    public JsonTools(){
        this.stringBuilder = new StringBuilder();
    }

    //修改后还原json字符串
    private void write(String hash, boolean add){
        if (!add) {
            stringBuilder.append(hash);
        }else {
            stringBuilder.append(hash).append(",");
        }
    }
    /**
     * 遍历json对象，每个值中插入标记
     * @niject 注入的参数
     * */
    //初始是jsonObject
    @SuppressWarnings("unchecked")
    public void jsonObjInject(Map<String, Object> jsonMap, String inject) {
        write("{", false);
        Iterator<Map.Entry<String, Object>> iterator = jsonMap.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
//                System.out.println("Key = " + key + " //JsonObject");
                write(String.format("\"%s\":{", key),false);
                Iterator<Map.Entry<String, Object>> iteratorValue = ((Map<String, Object>)value).entrySet().iterator();
                while (iteratorValue.hasNext()){
                    Map.Entry<String, Object> entryValue = iteratorValue.next();
                    if (entryValue instanceof HashMap) { //值也可能是对象
                        jsonObjInject((Map<String, Object>) entryValue, inject);
                    }else {//基础类型数据就是最里层的结果了 key:value
//                        System.out.println("--Key = " + entryValue.getKey() + ", Value = " + entryValue.getValue() + ", type: " + entryValue.getValue().getClass());
                        write(String.format("\"%s\":\"%s\"", entryValue.getKey(), entryValue.getValue() + inject), iteratorValue.hasNext());
                    }
                }
                write("}", iterator.hasNext());
            }else if (value instanceof ArrayList){ //json数组
                write(String.format("\"%s\":[", key), false);
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
//                System.out.println("Key = " + key + " //JsonArray");
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        jsonObjInject((Map<String, Object>) obj, inject);
                    }else { //要么就是基础类型数据了,就是最终结果了
//                        System.out.println("--Value = " + obj + ", type: " + obj.getClass());
                        write(String.format("\"%s\"", obj + inject), iteratorArray.hasNext());
                    }
                }
                write("]", iterator.hasNext());
            }else {//基础类型数据就是最里层的结果了 key:value
                write(String.format("\"%s\":\"%s\"",key, value + inject), iterator.hasNext());
//                System.out.println(String.format("Key = %s  Value = %s, type: %s",key, value, value.getClass()));
            }
        }
        write("}", false);
    }

    //初始是jsonArray的
    /**
     * 遍历json数组，每个值中插入标记
     * @niject 注入的参数
     * */
    @SuppressWarnings("unchecked")
    public void jsonArrInject(List<Object> jsonList, String inject) {
        write("[", false);
        Iterator<Object> iterator = jsonList.iterator();
        while (iterator.hasNext()){
            Object value = iterator.next();
//            System.out.println(value + " ,type: " + value.getClass());
            if (value instanceof HashMap){ //json对象数组
                jsonObjInject((Map<String, Object>)value, inject);
            }else {//基础类型数据就是最里层的结果了 value，value1，value2
                write(String.format("\"%s\"", value + inject), iterator.hasNext());
            }
        }
        write("]", false);
    }

    /**`
     * 解析json字符串里的对象，放回 Map
     * @param object
     * @return Map
     */
    @SuppressWarnings({"rawtypes" })
    public static Map jsonObjectToMap(Object object) {
        try {
            JSONObject jsonObject = new JSONObject(object.toString());
            Map<String, Object> objectMap = jsonObject.toMap();
            // 打印健值对看看
            // objectMap.forEach((key,value) -> System.out.println(key + "=" + value));
            return objectMap;
        } catch (Exception e) {
            BurpExtender.callbacks.printError("[jsonObjectToMap] " + e.getMessage());
        }
        return null;
    }

    // 解析json，然后添加注入字符
    // https://blog.csdn.net/zitong_ccnu/article/details/47375379
    public static String createJsonBody(String body, String injectStr){
        try {
            if (body.startsWith("{")){
                JSONObject jsonObject = new JSONObject(body);
                Map<String, Object> jsonMap = jsonObject.toMap();
                JsonTools jsonTools = new JsonTools();
                jsonTools.jsonObjInject(jsonMap, injectStr);
                return jsonTools.stringBuilder.toString();
            }else if (body.startsWith("[")){
                JSONArray jsonArray = new JSONArray(body);
                List<Object> jsonList = jsonArray.toList();
                JsonTools jsonTools = new JsonTools();
                jsonTools.jsonArrInject(jsonList, injectStr);
                return jsonTools.stringBuilder.toString();
            }
        } catch (Exception e) {
            BurpExtender.callbacks.printError("createJsonBody:\n" + e +
                    "\nerrorData:\n" + body);
        }
        //非json数据直接原文返回
        return body;
    }

    public static String createFormBody(String body, String injectStr){
        String[] qs = body.split("&");
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0;i<qs.length -1;i++){
            stringBuilder.append(qs[i]).append(injectStr).append("&");
        }
        stringBuilder.append(qs[qs.length-1]); //最后的参数不添加&
        return stringBuilder.toString();
    }

    /**
     * 遍历json对象，每个值中插入标记
     * @niject 注入的参数
     * */
    @SuppressWarnings("unchecked")
    public void jsonObjHandler(Map<String, Object> jsonMap, ParamHandlerImpl handler) {
        write("{", false);
        Iterator<Map.Entry<String, Object>> iterator = jsonMap.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
//                System.out.println("Key = " + key + " //JsonObject");
                write(String.format("\"%s\":{", key),false);
                Iterator<Map.Entry<String, Object>> iteratorValue = ((Map<String, Object>)value).entrySet().iterator();
                while (iteratorValue.hasNext()){
                    Map.Entry<String, Object> entryValue = iteratorValue.next();
                    if (entryValue instanceof HashMap) { //值也可能是对象
                        jsonObjHandler((Map<String, Object>) entryValue, handler);
                    }else {//基础类型数据就是最里层的结果了 key:value
//                        System.out.println("--Key = " + entryValue.getKey() + ", Value = " + entryValue.getValue() + ", type: " + entryValue.getValue().getClass());
                        List<ParamKeyValue> paramKeyValues = handler.handler(entryValue.getKey(), entryValue.getValue());
                        for (ParamKeyValue paramKeyValue :
                                paramKeyValues) {
                            write(String.format("\"%s\":\"%s\"", paramKeyValue.getKey(), paramKeyValue.getValue()), iteratorValue.hasNext());
                        }
                    }
                }
                write("}", iterator.hasNext());
            }else if (value instanceof ArrayList){ //json数组
                write(String.format("\"%s\":[", key), false);
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
//                System.out.println("Key = " + key + " //JsonArray");
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        jsonObjHandler((Map<String, Object>) obj, handler);
                    }else { //要么就是基础类型数据了,就是最终结果了
//                        System.out.println("--Value = " + obj + ", type: " + obj.getClass());
                        List<ParamKeyValue> paramKeyValues = handler.handler(key, obj);
                        for (ParamKeyValue paramKeyValue :
                                paramKeyValues) {
                            write(String.format("\"%s\"", paramKeyValue.getValue()), iteratorArray.hasNext());
                        }
                    }
                }
                write("]", iterator.hasNext());
            }else {//基础类型数据就是最里层的结果了 key:value
                List<ParamKeyValue> paramKeyValues = handler.handler(key, value);
                for (ParamKeyValue paramKeyValue :
                        paramKeyValues) {
                    write(String.format("\"%s\":\"%s\"", paramKeyValue.getKey(), paramKeyValue.getValue()), iterator.hasNext());
                }
//                System.out.println(String.format("Key = %s  Value = %s, type: %s",key, value, value.getClass()));
            }
        }
        write("}", false);
    }

    /**
     * 遍历json数组，每个值中插入标记
     * @niject 注入的参数
     * */
    @SuppressWarnings("unchecked")
    public void jsonArrHandler(List<Object> jsonList, ParamHandlerImpl handler) {
        write("[", false);
        Iterator<Object> iterator = jsonList.iterator();
        while (iterator.hasNext()){
            Object value = iterator.next();
//            System.out.println(value + " ,type: " + value.getClass());
            if (value instanceof HashMap){ //json对象数组
                jsonObjHandler((Map<String, Object>)value, handler);
            }else {//基础类型数据就是最里层的结果了 value，value1，value2
                List<ParamKeyValue> paramKeyValues = handler.handler("", value);
                for (ParamKeyValue paramKeyValue :
                        paramKeyValues) {
                    write(String.format("\"%s\"", paramKeyValue.getValue()), iterator.hasNext());
                }
            }
        }
        write("]", false);
    }
}
