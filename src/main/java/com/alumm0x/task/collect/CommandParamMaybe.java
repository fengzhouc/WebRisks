package com.alumm0x.task.collect;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.listensers.HttpRequestResponseWithMarkers;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.json.JsonTools;

import burp.BurpExtender;
import burp.IParameter;

public class CommandParamMaybe extends VulTaskImpl {

    String message = null;
    // 标记此次检测的编号
    String uuid = UUID.randomUUID().toString().substring(0, 8);

    public static VulTaskImpl getInstance(HttpRequestResponseWithMarkers requestResponse){
        return new CommandParamMaybe(requestResponse);
    }
    private CommandParamMaybe(HttpRequestResponseWithMarkers requestResponse) {
        super(requestResponse);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void run() {
        /**
         * 检测参数是否是命令
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), new ArrayList<>())){
            // 检查json数据
            if (BurpReqRespTools.getReqBody(requestResponse).length > 0
                && new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("{")){
                JsonTools tools = new JsonTools();
                try {
                    tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(requestResponse))), new ParamHandlerImpl() {
                        @Override
                        public List<ParamKeyValue> handler(Object key, Object value) {
                            List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                            if (isCommand(value.toString())) {
                                message = String.format("【%s】Json参数中含有疑似命令的参数值：%s=%s", uuid, key.toString(), value.toString());
                            }
                            paramKeyValues.add(new ParamKeyValue(key, value));
                            return paramKeyValues;
                        }
                    });
                } catch (Exception e) {
                    BurpExtender.callbacks.printError("[CommandParamMaybe.run] " + e.getMessage());
                }
            } else {
                // 检查请求的参数，使用burp解析的，包含如下:查询参数/cookie/form参数
                for (IParameter parameter : BurpExtender.helpers.analyzeRequest(requestResponse).getParameters()) {
                    if (isCommand(parameter.getValue())) {
                        message = String.format("【%s】查询参数/cookie/form参数中含有疑似命令的参数值：%s=%s", uuid, parameter.getName(), parameter.getValue());
                    }
                }
            }
            if (message != null) {
                //不需要发包,上面正则匹配到则存在问题
                // 记录日志
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPath(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    CommandParamMaybe.class.getSimpleName(),
                    String.join(",", message), 
                    null);
            }
        }
    }

    /**
     * 判断是否命令
     * @param value
     * @return
     */
    public boolean isCommand(String value) {
        for (String command : SourceLoader.loadSources("/payloads/Commands.bbm")) {
            if (value.toLowerCase().startsWith(command)) {
                return true;
            }
        }
        return false;
    }
}
