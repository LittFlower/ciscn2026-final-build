**选手附件包**

你们拿到的是某企业 2026-07-02 00:00 到 2026-07-06 13:30 的多源日志。请基于日志和资产清单，提交攻击线索、攻击时间线、IOC 和攻击路径拓扑。

公开数据包含：

- `env/`：资产、账号、网段、服务关系和已知维护窗口。
- `logs/`：边界、网络、Linux、Windows、应用、数据库、云审计和安全告警日志。
- `artifacts/`：PCAP、Windows Event XML 导出等正式证据素材，内含 artifact 事件索引。
- `docs/`：选手手册、日志字段说明、提交格式说明、枚举值和样例提交。
- `tools/`：提交格式校验器、CSV 转攻击图工具和攻击图渲染辅助工具。

提交文件固定为：

```text
submission.zip
  manifest.json
  evidence.csv
  timeline.csv
  attack_graph.json
  ioc.csv
```

其中 `attack_graph.json` 可以直接编写，也可以先写 `graph_nodes.csv` 和 `graph_edges.csv`，再用 `tools/build_attack_graph.py` 生成。

建议先阅读 `docs/player_manual.md`，再查看 `docs/sample_submission/`。

注意：不是所有可疑事件都是攻击事件。平台评分会同时考虑召回率和准确率，过量提交无关日志会影响得分。

每队使用唯一 token 认证，正式提交最多上传 3 次；单个 `submission.zip` 不得超过 30 MB。
