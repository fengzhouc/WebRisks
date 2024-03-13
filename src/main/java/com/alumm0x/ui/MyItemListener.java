package com.alumm0x.ui;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JCheckBox;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.util.ClassNameGet;

import burp.IBurpExtenderCallbacks;

public class MyItemListener implements ItemListener {

    // 标记是否全部勾选
    boolean isAll = false;
    // 记录all的checkbox
    JCheckBox all = null;
    // 记录仅能通过自勾选的方式开启，不受all控制的任务
    static List<String> need = new ArrayList<>();
    static {
        need.add("XssStore");
        need.add("Fuzz");
        need.add("Cve");
        need.add("BypassWaf");
    }

    public void itemStateChanged(ItemEvent e) {
        JCheckBox jcb = (JCheckBox) e.getItem();// 将得到的事件强制转化为JCheckBox类
        String key = jcb.getText(); //任务的名称
        if (jcb.isSelected()) {// 判断是否被选择
            // 选中则创建对象，存入检查列表
            if (key.equalsIgnoreCase("All")){
                isAll = true;
                all = jcb;
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (!need.contains(t.getText()) && !t.isSelected()) {
                        t.setSelected(true);   
                    }
                }
            }else if (key.equalsIgnoreCase("Collect")){
                // 信息采集的类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.collect", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("Api")){
                // 漏洞api的探测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.api", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("Config")){
                // 安全配置的检测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.config", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("WebBasic")){
                // web基础漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.webbasic", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("Cve")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.cves", true)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("Fuzz")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.fuzz", true)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("BypassWaf")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.bypasswaf", true)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("SessionInvalid")) {
                // 绑定IDOR跟SessionInvalid的关系，如果SessionInvalid开了，那IDOR也必须开
                TaskManager.tasks.add("com.alumm0x.task.SessionInvalid");
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (t.getText().equalsIgnoreCase("IDOR")) {
                        t.setSelected(true);
                        break;
                    }
                }
            }else if (key.equalsIgnoreCase("proxy")) {
                MainPanel.intercepts.put(key, IBurpExtenderCallbacks.TOOL_PROXY);
            }else if (key.equalsIgnoreCase("repeater")) {
                MainPanel.intercepts.put(key, IBurpExtenderCallbacks.TOOL_REPEATER);
            }else {
                // 其他勾选的就在这里处理，也就是task这个包下的检测类了（不含子包的）
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task", false)) {
                    String[] l = task.split("\\.");
                    if (key.equalsIgnoreCase(l[l.length - 1])) {
                        TaskManager.tasks.add(task);
                        break;
                    }
                }
            }
            // 检查是否全部勾选，只有未触发过全勾选的情况下才进行检查
            if (!isAll) {
                boolean status = true; // 记录检查状态,默认为true，发现一个未勾选的则为false 
                for (JCheckBox t : MainPanel.taskJBS) {
                    // 发现有存在未勾选的
                    if (!t.getText().equalsIgnoreCase("all") && !need.contains(t.getText()) && !t.isSelected()) {
                        status = false; // 设置标签
                        break;
                    }
                }
                // 如果全部勾选，则同步勾选all
                if (status && all != null) {
                    all.setSelected(true);   
                }
            }
        } else {
            // 去勾选，则从列表中删除（去勾选没有特例，全部都去掉）
            // isAll,需要是直接触发的去勾选all才会把所有的去勾选了
            if (key.equalsIgnoreCase("All") && isAll){
                isAll = false;
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (t.isSelected()) {
                        t.setSelected(false);   
                    }
                }
            }else if (key.equalsIgnoreCase("Collect")){
                // 信息采集的类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.collect", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("Api")){
                // 漏洞api的探测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.api", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("Config")){
                // 安全配置的检测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.config", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("WebBasic")){
                // web基础漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.webbasic", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("Cve")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.cves", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("Fuzz")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.fuzz", true)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("BypassWaf")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.bypasswaf", true)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("IDOR")) {
                // 绑定IDOR跟SessionInvalid的关系，如果SessionInvalid开了，那IDOR也必须开
                TaskManager.tasks.remove("com.alumm0x.task.IDOR");
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (t.getText().equalsIgnoreCase("SessionInvalid")) {
                        t.setSelected(false);
                        break;
                    }
                }
            } else if (!key.equalsIgnoreCase("proxy") && !key.equalsIgnoreCase("repeater")) {
                // 其他勾选的就在这里处理，也就是task这个包下的检测类了（不含子包的）
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task", false)) {
                    String[] l = task.split("\\.");
                    if (key.equalsIgnoreCase(l[l.length - 1])) {
                        TaskManager.tasks.remove(task);
                        break;
                    }
                }
            }else {
                MainPanel.intercepts.remove(key);
            }
            // all勾选过才会触发，勾选过才需要任意去勾选时去勾选all
            if (!need.contains(key) && !key.equalsIgnoreCase("all") && all != null) {
                isAll = false; // 标记并不是直接触发的all，不需要去勾选所有
                all.setSelected(false);   
            }
        }
    }
}
