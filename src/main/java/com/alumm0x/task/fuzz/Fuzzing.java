package com.alumm0x.task.fuzz;

/**
 * 对于API的安全风险，使用Fuzz的方式进行发现
 * Fuzz思路
 * 参数污染：传统方式，但也有不同
 * 1.目前请求参数结构都很复杂，json、form、xml，如何能遍历到每个参数是重点
 * 2.nday的poc无法深入到具体的参数
 * 3.非预期参数值导致的服务异常，如boolean改传String
 * 4.参数值编码问题，这通常都是人工识别的
 * 5.畸形数据注入，比如控制字符，注释符，运算符等用来绕过一些安全设备
 * 参数结构变异：这个其实深有体会，为了API通用，开发者可能会设计API接受并非该接口所需的参数，或者是因为迭代，遗留了一些参数
 * 1.新增参数（隐藏参数的发现）
 * 2.删除参数（遇到过绕过鉴权）
 * 3.数据类型替换，如json数据，本来是元素值单个值，替换成对象
 * 
 * 结果预判
 * 1.参数污染/结构变异：响应内容跟原来不同，即需要关注
 * 2.nday探测：特殊的验证效果，大多数类型还是根据响应了（不排除有我不知道的情况）
 *   - 实现独立的dnslog监听器（单例，避免创建多个dnslog导致卡顿），fuzz启动时进行监听，CallBack识别到此次使用了dnslog则查看监听情况
 *   - 延时payload检测，有些payload是延时效果的，CallBack需要包含此类研判方式
 * 难点：这里主要难在于CallBack的兼容实现，以及如果知道此次payload是属于哪种
 * 
 * 参考资料：
 * https://www.anquanke.com/post/id/282840
 * https://mp.weixin.qq.com/s?__biz=Mzg3NDcwMDk3OA==&mid=2247484068&idx=1&sn=89ea1b1be48a0cb7f93a4750765719d1&chksm=cecd8b79f9ba026f7fbf52771e41272d684fc3af5175587f768082f8dbaee12d6d33bb892ceb&scene=21#wechat_redirect
 * https://github.com/s0duku/ProxyFuzzer
 */
public class Fuzzing {
    
}
