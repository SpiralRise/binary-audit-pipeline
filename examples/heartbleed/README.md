# 案例：OpenSSL 1.0.1c（Heartbleed 同版本）无源码审计

## 样本是什么

从 Ubuntu 12.04 官方归档下载的 `openssl` 二进制包，解包后得到：

```
lib/x86_64-linux-gnu/libssl.so.1.0.0
lib/x86_64-linux-gnu/libcrypto.so.1.0.0
usr/bin/openssl
usr/lib/x86_64-linux-gnu/openssl-1.0.0/engines/*.so
```

包名里的 `1.0.0` 是 Ubuntu 的 SONAME，实际版本看字符串：

```bash
strings libssl.so.1.0.0 | grep "OpenSSL 1"
# SSLv3 part of OpenSSL 1.0.1c 10 May 2012
# TLSv1 part of OpenSSL 1.0.1c 10 May 2012
```

也就是说这个样本的版本是 **1.0.1c**，属于 CVE-2014-0160（Heartbleed）的影响范围，
而且已经被 `strip`，没有任何符号表。

## 怎么跑

```bash
python3 audit.py /path/to/openssl-1.0.1c/extracted /path/to/out
```

默认关闭 CVE 扫描（第 1 步），开启 Joern（第 6 步）。

## 跑出来的结果

| 步骤 | 结果 |
| --- | --- |
| 1. 组件 CVE（cve-bin-tool，默认关闭） | 0（本次未开启，数据库也未初始化） |
| 2. 能力特征（capa） | 81 条，命中 10 个文件 |
| 3. CWE 缺陷（cwe_checker） | 162 条 |
| 4. 反编译产物（Ghidra） | 8735 个函数 |
| 5. 伪代码规则（Semgrep） | 195 条 |
| 6. 污点路径（Joern） | 25 条；sink 命中 960 条，其中危险调用 6 条 |
| 7. 脚本扫描（Semgrep/Bandit/njsscan） | 0（样本里没有脚本，自动跳过） |

capa 命中数最多的三个文件：

| 文件 | 规则 | 函数 |
| --- | --- | --- |
| `libcrypto.so.1.0.0` | 39 | 1077 |
| `usr/bin/openssl` | 24 | 104 |
| `libssl.so.1.0.0` | 6 | 106 |

## 6.2 危险 sink 表（节选）

| 位置 | 函数 | 调用 |
| --- | --- | --- |
| openssl.c:19359 | `FUN_00424d40` | `memcpy(local_60, pAVar1->data, (long)pAVar1->length)` |
| openssl.c:20649 | `password_callback` | `memcpy(param_1, pcVar6, (long)(int)len)` |
| openssl.c:24059 | `generate_cookie_callback` | `memcpy(param_2, local_78, (ulong)local_9c)` |
| libgost.so.c:5091 | `FUN_0010cd40` | `memcpy((void *)((long)param_1 + (long)iVar3 + 0x54), param_2, __n)` |

第一条值得注意：拷贝长度 `pAVar1->length` 直接来自结构体字段，
和 Heartbleed 的形态（长度字段来自报文、未经校验就传给 `memcpy`）一致。

## 这个案例能说明什么，不能说明什么

能说明：

- 对 stripped 的二进制，流水线能自动定位到"长度字段直接进 `memcpy`"这类调用点，
  把 8735 个反编译函数压缩成 6 条值得人工看的危险调用；
- 不需要源码、不需要运行样本。

不能说明：

- 这不是"自动发现了 CVE-2014-0160"。函数被 strip 后只剩 `FUN_00424d40` 这种名字，
  静态扫描只能给出行为线索，不能证明它就是 `tls1_process_heartbeat`；
- CVE 编号要靠第 1 步的 cve-bin-tool，本次是关闭状态，而且它按版本匹配，
  对 Ubuntu 打了补丁的包容易误报或漏报；
- 结论仍然需要人工顺着这条 `memcpy` 往上回溯，确认长度字段是否来自网络报文。

这也是这个项目的定位：它不是漏洞发现器，是把"该先看哪里"从几千个函数缩短到几条线索。
