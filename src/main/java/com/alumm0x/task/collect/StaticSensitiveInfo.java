package com.alumm0x.task.collect;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticSensitiveInfo extends VulTaskImpl {

    /* 
     * 识别响应中是否包含敏感信息";
     */
    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new StaticSensitiveInfo(requestResponse);
    }
    private StaticSensitiveInfo(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // -响应中的敏感信息
        byte[] body = BurpReqRespTools.getRespBody(requestResponse);
        // 1.get请求获取数据才可能存在批量泄漏信息的可能，post/put/patch这种是更新数据，一般是单一用户信息
        // 2.有查询参数，这样才有批量的可能
        // 3.有响应才检测
        if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("get")
                && BurpReqRespTools.getQuery(requestResponse) != null
                && body.length > 0) {
            String body_str = new String(body);
            String desc = null;
            //先检测是否存在url地址的参数，正则匹配
            String UIDRegex = "['\"&<;\\s/,][1-9]\\d{5}(18|19|([23]\\d))\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d{3}[0-9Xx]['\"&<;\\s/,]"; //身份证的正则
            String phoneRegex = "['\"&<;\\s/,]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]+?"; //手机号的正则
            String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
            Pattern patternUID = Pattern.compile(UIDRegex);
            Pattern patternPhone = Pattern.compile(phoneRegex);
            Pattern patternEmail = Pattern.compile(emailRegex);
            Matcher matcherUid = patternUID.matcher(body_str);
            Matcher matcherPhone = patternPhone.matcher(body_str);
            Matcher matcherEmail = patternEmail.matcher(body_str);
            if (matcherUid.find()) {
                desc += "UID";
                desc += "\n" + matcherUid.group();
                while (matcherUid.find()) { //每次调用后会往后移
                    desc += "\n" + matcherUid.group();
                }
                desc += "\n";
            }
            if (matcherPhone.find()) {
                desc += "Phone";
                desc += "\n" + matcherPhone.group();
                while (matcherPhone.find()) { //每次调用后会往后移
                    desc += "\n" + matcherPhone.group();
                }
                desc += "\n";
            }
            if (matcherEmail.find()) {
                desc += "Email";
                desc += "\n" + matcherEmail.group();
                while (matcherEmail.find()) { //每次调用后会往后移
                    desc += "\n" + matcherEmail.group();
                }
                desc += "\n";
            }
            // 记录日志
            MainPanel.logAdd(
                requestResponse, 
                BurpReqRespTools.getHost(requestResponse), 
                BurpReqRespTools.getUrlPath(requestResponse),
                BurpReqRespTools.getMethod(requestResponse), 
                BurpReqRespTools.getStatus(requestResponse), 
                StaticSensitiveInfo.class.getSimpleName(),
                "敏感信息泄漏风险", 
                desc);
        }
    }
}

