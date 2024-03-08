package com.alumm0x.util.param;


import java.util.List;

/**
 * 用于处理json数据的类，可以继承复写相关方法
 */
public abstract class ParamHandlerImpl {
    /**
     * 用于实现吹了健值对的逻辑（如果想实现查找的话，可以返回null，这样最上层也会返回null，这样就可以感知到存在查找的目标）
     * 查：返回null，最上层会触发空指针异常，捕获处理查询结果
     * 增：可以在指定key后面增加健值对
     * 删：设置ParamKeyValue的delete属性，以控制删除
     * @param key 健
     * @param value 值
     * @return JsonKeyValue
     */
    abstract public List<ParamKeyValue> handler(Object key, Object value);
}

