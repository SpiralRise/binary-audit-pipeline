# binary-audit-pipeline

[English](README.md) | **简体中文**

> 一条命令，把无源码二进制目录变成一份按优先级排序的高风险点清单：
> 能力特征、CWE 缺陷、反编译代码、污点路径，以及下一步 fuzz 建议。

<p align="center">
  <img src="docs/demo.gif" alt="对 strip 过的 OpenSSL 1.0.1c 二进制运行流水线" width="800">
</p>

## 为什么做这个

只有二进制、没有源码时，常见流程是：跑 capa、跑 cwe_checker、打开 Ghidra、
对伪代码跑 Semgrep、再跑 Joern 做污点分析，最后手工合并五种输出。
这个项目把它们串起来，生成一份按优先级排序的 Markdown 报告。

它不是 fuzzer，也不执行样本。它是一个静态审计流水线，告诉你先看哪里。

## 它做什么

| 步骤 | 工具 | 作用 | 默认 |
| --- | --- | --- | --- |
| 1 | cve-bin-tool | 按版本查已知 CVE | 关 |
| 2 | capa | 能力识别：文件 -> 函数 -> 规则 | 开 |
| 3 | cwe_checker | CWE 缺陷，区分真实缺陷与 CWE676 提示 | 开 |
| 4 | Ghidra | 只反编译 capa/CWE 命中的文件（`GHIDRA_SCOPE=hits`） | 开 |
| 5 | Semgrep | 用本地规则扫描伪代码 | 开 |
| 6 | Joern | source-to-sink 污点路径，带文件、函数、行号、代码 | 开 |
| 7 | Semgrep + Bandit + njsscan | 检查 shell/Python/JS 脚本中的危险调用 | 开 |
| 8 | 汇总 | 生成 `高风险点清单.md` | 开 |

几个关键行为：

- Ghidra 只反编译 capa/cwe_checker 命中的文件；都没命中时回退全量；
- CWE 结果区分真实缺陷和几乎每个 ELF 都会出现的 CWE676 提示；
- Joern 的每条 flow 都带源文件、函数、行号和代码片段；
  单节点自环和 sink 名单里的 source 函数会被过滤；
- 报告里有独立的危险 sink 表，`memcpy`、`strcpy`、`system` 一目了然。

## 这几步是怎么串起来的

这 8 步是一条漏斗，每一步都在为下一步缩小范围：

1. **CVE 检查**（可选）按版本比对已知 CVE；
2. **capa + cwe_checker** 扫目标目录里的全部文件：capa 给出能力标签
   （网络通信、文件处理、编码解码、加解密），cwe_checker 给出内存安全和其它 CWE 缺陷；
3. 两个工具命中的文件**去重**后，作为 **Ghidra 的逆向范围**；没被命中的直接跳过，
   几千个函数因此收敛到几百个。如果全都没命中，Ghidra 回退到全量反编译；
4. **Semgrep** 在伪代码上做初筛，只有命中危险模式的文件进入 **Joern 范围**；
5. **Joern** 复筛，确认不可信输入是否真的流到 sink，并给出文件、函数、行号；
6. 同时用 **Semgrep + Bandit + njsscan** 分析目录里的 shell / Python / JS 脚本；
7. **汇总**成 `高风险点清单.md`。

每一步的原始结果都写在自己的编号目录里（`01_cve`、`02_capa`……）。所以跑完的步骤
会自动跳过、中断后能续跑、可以用 `--only` 只重跑某一步；整个 `out/` 目录也可以直接
交给 AI 或同事做下一步分析。

## 快速开始

### Docker

```bash
docker pull ghcr.io/spiralrise/binary-audit-pipeline:1.1.0

python3 audit.py /path/to/firmware /path/to/out
```

`audit.py` 是对 `docker run` 的简单封装：挂载输入目录（只读）和输出目录，
并传入常用环境变量。

### 直接运行容器

```bash
docker run --rm --entrypoint sh \
  -e WITH_JOERN=1 \
  -e GHIDRA_SCOPE=hits \
  -v /path/to/firmware:/work/targets:ro \
  -v /path/to/out:/work/out \
  ghcr.io/spiralrise/binary-audit-pipeline:1.1.0 \
  /opt/pipeline/scripts/pipeline.sh /work/targets /work/out
```

### 离线

```bash
zstd -d binary-audit-pipeline.tar.zst -c | docker load
tar xzf binary-audit-pipeline-tools.tar.gz
python3 audit.py /path/to/samples /path/to/out
```

离线包体积较大，不放在仓库里；可以用
`docker save binary-audit-pipeline:1.1.0 | zstd -T0 -10 -o binary-audit-pipeline.tar.zst`
自行生成。

## 环境要求

- Docker Engine 20.10+（或 Docker Desktop）；
- 约 10GB 可用磁盘（镜像 + 输出目录）；
- 4 核 CPU 对中等规模的二进制足够；
- 8GB 内存起步，建议 16GB，Ghidra 和 Joern 比较吃内存。

## 实测性能

4 核 / 16GB 内存的虚拟机上，对一个 strip 过的 `libssl.so.1.0.0`
（Ubuntu 12.04 自带的 OpenSSL 1.0.1c，约 8700 个函数）跑完整 8 步（含 Joern）
约 **25 分钟**。耗时主要在 Ghidra 反编译和 Joern 污点分析，其余步骤合计几分钟。

因为每一步的结果都落盘缓存，中断后可以直接续跑，也可以用 `--only 8` 只重跑汇总。

## 输出

主报告是 `out/高风险点清单.md`，包含：

- 按文件、规则、函数分组的能力命中；
- CWE 缺陷，CWE676 提示单独列出；
- 反编译函数清单；
- Semgrep 结果；
- 脚本扫描结果（Semgrep、Bandit、njsscan）；
- 按起点文件分组的 Joern 污点路径；
- 危险 sink 表。

原始工具输出保留在 `out/01_cve`、`out/02_capa` 等目录，方便查看 JSON。

![危险 sink 表](docs/sink-table.png)

## 架构

```mermaid
flowchart LR
  A[目标目录] --> B[capa]
  A --> C[cwe_checker]
  B --> D[Ghidra 范围选择]
  C --> D
  D --> E[Ghidra 反编译]
  E --> F[Semgrep]
  E --> G[Joern]
  A --> H[脚本扫描]
  B --> I[汇总]
  C --> I
  F --> I
  G --> I
  H --> I
  I --> J[高风险点清单.md]
```

### 设计思路：做漏斗，不做并联

五个工具各自跑全量再合并，看起来更简单，实际噪音压不住：cwe_checker 在几乎每个
ELF 上都会报 CWE676；一个 `libssl.so` 全量反编译就是八千多个函数；给每个函数都
建 Joern CPG 会直接 OOM。

三个决策决定了运行时间和报告的可读性：

1. **Ghidra 只反编译 capa / cwe_checker 命中的文件**，两者都没命中时才回退全量。
2. **Joern 只对 Semgrep 选中的伪代码建图**。Semgrep 回答“这里有没有危险调用”，
   Joern 回答“外部输入能不能走到这里”。
3. **每一步写自己的编号目录**，所以可以断点续跑、单独重跑某一步，原始 JSON 也
   始终保留，方便人工或 AI 复查。

踩过的坑：每个工具的 JSON 结构都不一样（所以有了一份统一的中间结构）；CWE676
会淹没真实缺陷（所以单独统计）；伪代码行号不是源码行号（报告里明说了）。

## 从审计到 fuzz

静态审计只有能引导下一步才有价值。仓库里带了
[`prompts/fuzz-plan.md`](prompts/fuzz-plan.md)，把整个 `out/` 目录交给 AI，
它会：

1. 检查目标目录里是否有需要 `binwalk` 的压缩包/固件镜像；
2. 读 capa、CWE、Semgrep、Joern、脚本扫描结果；
3. 排序适合 fuzz 的函数；
4. 建议 harness（AFL++ / libFuzzer）和输入格式；
5. 列出没有被覆盖的文件。

同样的内容也打包成了 agent skill：
[`skills/binary-audit-triage/SKILL.md`](skills/binary-audit-triage/SKILL.md)，
支持 skill 的运行时会自动加载。

## 案例

[`examples/heartbleed/`](examples/heartbleed/) 用一段 strip 过的 OpenSSL 1.0.1c
二进制（Heartbleed 同版本）跑完整流程：88 个文件进去，得到 10 个反编译文件、
8735 个函数、33 条污点路径、81 条危险 sink。页面上有终端运行截图，也写清了
这个结果能说明什么、不能说明什么。

## 限制

- 只做静态分析，发现需要人工确认；
- 不执行样本，不是 fuzzer；
- 加壳/混淆需要先脱壳；
- zip、固件镜像需要先 `binwalk` 解包；
- Joern 只覆盖 Semgrep 选中的范围，不是所有函数；
- 反编译代码不是原始源码，行号是伪代码行号。

## 仓库结构

```text
audit.py            宿主机一键封装脚本
scripts/            流水线与辅助脚本
ghidra_scripts/     Ghidra headless 导出脚本
rules/local/        针对伪代码的 Semgrep 规则
cwe_pcode/          打过补丁的 cwe_checker p-code 提取器（适配 Ghidra 12.x）
samples/            小型演示样本源码
prompts/            AI 交接提示词
skills/             agent skill（支持 skill 的运行时会自动加载）
examples/           案例（如 Heartbleed）
docs/               截图与架构图
LICENSE
THIRD_PARTY_LICENSES.md
CONTRIBUTING.md
```

## 参与贡献

欢迎提 Issue 和 PR。流水线本身就是 `scripts/` 下的一组 shell / Python 脚本，
每一步相互独立，改一个地方通常只动一个文件。

- 超过 bug 修复的改动，先开 Issue 说清楚再动手；
- 新行为用环境变量开关控制（和现有的 `WITH_*`、`GHIDRA_SCOPE` 保持一致），
  不要改变默认路径的行为；
- 提 PR 之前先在一个小目录（几个 ELF 文件）上跑通。

细节见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

## 许可证

MIT。第三方工具和规则保留各自许可证，见
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)。

## 免责声明

本项目仅用于授权的安全测试与研究。请勿用于未授权的系统。

---

作者：SpiralRise
