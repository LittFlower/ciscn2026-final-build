# 本地 Benchmark

默认命令现在模拟已观察到的远端评分入口：

```bash
python3 benchmark/score_submission.py submission.zip
```

远端模式只对实际将上传的 ZIP 内容解包评分，不再对旁边的目录评分。若保留目录工作流，请显式指定实际压缩包：

```bash
python3 benchmark/score_submission.py submit --zip submission.zip
```

它输出 `Remote-score estimate`，而不是把严格的证据审计分数冒充为远端分数。

## 已对齐的远端行为

通过只读查看平台页面，已确认并在 `remote_profile.json` 中固化：

- 上传为 ZIP，页面标示最大 30 MB（本地暂按 `30 * 1024 * 1024` 字节预检）；
- ZIP 根目录包含五个核心文件，或使用《选手手册》允许的一层包装目录；
- 共有格式、证据、阶段、时间线、节点、边、IOC 七个分项，权重为 `10+25+10+15+10+20+10`；
- `manifest.json` 的 `team_id` 必须绑定登录队伍，本地会从 `readme-team*.txt` 自动读取，或可用 `--team-id team57` 指定；
- 格式无效的上传也会消耗一次机会；
- 每队最多 3 次，保留历史最高分。

本地格式项调用题目提供的 `tools/validator.py`。ZIP 会检查大小、重复文件、危险路径、符号链接、加密成员，以及五个文件是否位于压缩包根目录或单层包装目录；随后只在本地解包安全上限内读取这五个归一化后的文件进行评分。解压上限是本地防 ZIP 扩展攻击的保护，并非对远端上限的推断。它不会上传文件。若无法解析本地队伍 ID，报告会标为 `Submission eligibility: UNKNOWN`，而不会给出可提交的远端分数。

## 远端分数估计模型

远端隐藏答案和匹配阈值没有暴露，因此 `score_remote.py` 使用 source oracle 的正确事实集，并采用透明、保守的部分匹配：

| 项目 | 本地远端估计 |
| --- | --- |
| 证据/阶段 | 精确 event ID 和 stage 覆盖；每条未审阅候选证据都会降低保守精度。 |
| 时间线 | 阶段、证据 F1、时间端点/时间窗重叠的一对一部分匹配；没有引用证据不得分，未匹配的额外行会降低精度。 |
| 节点 | 精确 `id,type` 覆盖，额外节点不直接扣分。 |
| 边 | 精确 `from,to,action,stage`，且必须有引用证据，才按证据 F1 和时间给部分分；未匹配的额外边会降低精度。 |
| IOC | 规范化的 `type,value` 一对一匹配；IP/域名不区分大小写，Windows 路径统一分隔符和大小写，POSIX 路径及命令保留大小写；没有时间或引用证据支撑的身份匹配不得分。 |

默认时间容差为 90 秒，是公开信息无法确定时的透明假设，可改为：

```bash
python3 benchmark/score_submission.py submission.zip --time-tolerance-seconds 30
```

因此，这个分数是当前最接近可观察远端契约的预测，不是已破解的服务器评分函数。当前 profile 会明确标记为 `UNCALIBRATED`，在没有受控远端观测前不应把它作为官方分数。

## 严格正确性审计

提交前仍应运行 source-correctness。它以原始日志/物证为准，要求原子时间线、完整证据闭环、正确图边方向和 IOC 时间范围：

```bash
python3 benchmark/score_submission.py submit --mode correctness
# 或
python3 benchmark/score_correctness.py submit
```

source oracle 当前含 101 条事件、38 个原子步骤、27 个节点、37 条边和 21 个 IOC，并校验关键原始字段，如 Kubernetes token review、IAM role assumption 和对象存储 list/get。

严格审计还会校验 `source_manifest.json`：它锁定 48 个原始日志、环境资产清单、索引、PCAP 与 Windows XML 文件的 SHA-256，并直接核对 8 条计分 artifact 的 PCAP/XML 时间、端点、HTTP 请求或 Windows 字段及记录定位。`source_provenance.json` 还锁定 110 条计分/负控事件的来源位置和规范化记录哈希；`source_oracle_lock.json` 则独立锁定阶段、时间线、节点、边、IOC 和断言等已审阅语义。源数据被改写、重复 event ID、事件来源或 oracle 语义漂移，或 artifact 索引与原始工件不一致时，评分会拒绝运行。只有在重新审计后才可更新这些锁：

```bash
python3 benchmark/generate_source_manifest.py --check
python3 benchmark/generate_source_provenance.py --check
python3 benchmark/generate_source_oracle_lock.py --check
# 完成重新审计后才允许：
python3 benchmark/generate_source_manifest.py --write --confirm-reviewed-source-corpus
python3 benchmark/generate_source_provenance.py --write --confirm-reviewed-source-corpus
python3 benchmark/generate_source_oracle_lock.py --write --confirm-reviewed-oracle
```

`source_oracle.json` 的 `claim_caveats` 还会显式列出相关性或推断性结论，例如凭据文件与后续账号使用的关联、Jenkins 与 Runner 的时间关联、以及 PCAP 虚拟主机别名。它们会出现在严格评分报告中，避免把相关性直接表述为单条原始记录的事实。

## 模式与验证

```bash
# 远端估计器自测和回归
python3 benchmark/score_submission.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/test_score_remote.py

# 严格正确性审计自测
python3 benchmark/score_correctness.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/test_source_correctness.py

# 旧的 reference 一致性回归工具
python3 benchmark/score_submission.py submit --mode reference
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/test_score_submission.py
```

如果需要把估计器进一步校准到隐藏服务端的具体阈值，唯一可靠途径是一次经用户明确授权的、可控的真实上传实验；平台明确说明无效上传同样会占用 3 次额度。
