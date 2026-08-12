**选手手册**

**一、任务目标**

数据包模拟某大型企业 2026-07-02 00:00 至 2026-07-06 13:30 的安全运营数据。你们需要设计分析流程，从正常业务噪声中确认攻击证据，还原攻击时间线、并行横向路径、攻击图和 IOC，并提交固定格式的机器可读结果。

所有分数均由平台按固定规则自动计算，不设置人工说明分。


**二、核心提交文件**

```text
manifest.json
evidence.csv
timeline.csv
attack_graph.json
ioc.csv
```

`graph_nodes.csv`、`graph_edges.csv` 仅用于本地生成 `attack_graph.json`，不由平台读取。完整字段定义见 `docs/submission_schema.md`。

**三、正式证据源**

以下素材均可能包含标准答案证据：

- `logs/`：边界、网络、Linux、Windows、应用、数据库、云平台和安全设备日志。
- `artifacts/pcap/edge_trace_20260706.pcap`：包含关键网络包和大量正常背景包。
- `artifacts/windows_event_exports/*.evtx.xml`：包含关键 Windows Security/Sysmon 事件和大量正常事件。

PCAP 与 Windows XML 不是辅助材料。

引用方法：

- 普通日志：直接使用记录中的 `event_id`。
- PCAP：定位 packet 后，在 `pcap_manifest.csv` 中按 `record_ref=packet:<编号>` 取得 `event_id`。
- Windows XML：使用每条 `<Event>` 内的 `EventData/ArtifactEventId`。
- `artifact_event_index.csv` 是全量定位索引，不标记哪些记录属于攻击。

**四、注意事项**


为避免通过堆叠可疑事件刷分，证据发现和图谱关系评分均强调准确率与召回率的平衡。选手应提交经过分析确认的攻击证据，而不是提交全部可疑日志。

**五、攻击图规则**

节点类型只能为：

```text
ip host account bucket cluster database domain file network process service token
```

节点 ID 必须采用 `type:value`，例如：

```text
ip:192.0.2.234
host:sample-host
account:EXAMPLE\svc_demo
file:/tmp/example.bin
```

攻击图只提交已经成功发生、且能由所引证据确认的因果关系。失败登录、被拒绝访问、已阻断尝试、例行扫描、正常运维和正常备份不是攻击路径边。

**六、推荐解题工作流**

1. 读取 `env/`，建立资产、账号、服务和网段基线。
2. 将各日志源和 artifact 索引归一化为统一事件表。
3. 用时间、账号、源/目的地址和会话关系做多源关联。
4. 区分成功行为与失败/阻断/正常背景行为。
5. 先生成 `evidence.csv`，再由证据构造时间线、图边和 IOC。
6. 检查跳板形成后的并行分支是否完整汇聚到最终行为。
7. 使用公开工具校验和渲染，再打包上传。

**七、工具用法**

生成攻击图：

```bash
python3 tools/build_attack_graph.py docs/sample_submission/graph_nodes.csv docs/sample_submission/graph_edges.csv /tmp/sample_attack_graph.json
```

渲染为 Mermaid：

```bash
python3 tools/render_attack_graph.py /tmp/sample_attack_graph.json /tmp/sample_attack_graph.mmd
```

校验样例：

```bash
python3 tools/validator.py docs/sample_submission --logs logs --artifacts artifacts
```

校验正式目录：

```bash
python3 tools/validator.py your_submission_dir --logs logs --artifacts artifacts
```

`validator.py` 只验证公开 schema、枚举、时间和引用关系，不包含标准答案，也不预测得分。

**八、打包要求**

ZIP 根目录可直接放置五个核心文件，或使用一层包装目录并将五个文件直接置于其中；不允许更深目录。提交前必须确认 `manifest.json` 中的 `team_id` 与 token 对应编号一致。
