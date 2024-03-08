package com.alumm0x.util.param;

/**
 * 用户保存健值对
 */
public class ParamKeyValue {

    private final Object Key;
    private final Object Value;
    private boolean delete = false; //用于控制删除健值对


    public ParamKeyValue(Object key, Object value) {
        this.Key = key;
        this.Value = value;
    }

    public Object getKey() {
        return Key;
    }

    public Object getValue() {
        return Value;
    }

    public boolean isDelete() {
        return this.delete;
    }

    public void setDelete(boolean delete) {
        this.delete = delete;
    }
}
