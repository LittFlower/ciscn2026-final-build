**日志说明**

所有日志和正式 artifact 证据都包含可提交的 `event_id`。CSV 和 JSONL 日志直接提供 `event_id` 字段，纯文本日志使用 `event_id=<id>` 前缀。PCAP 使用 `artifacts/pcap/pcap_manifest.csv` 将 packet 映射到 `event_id`；Windows Event XML 在 `EventData/ArtifactEventId` 中给出 `event_id`。选手提交证据时应引用这些 `event_id`。

通用字段：

- `event_id`：平台评分点。
- `timestamp` 或 `time`：主办方归一化后的时间，时区为 `+08:00`。
- `src_ip` / `dst_ip`：来源和目标 IP，部分日志可能为空。
- `user` / `actor` / `db_user`：账号字段，不同日志源命名不同。
- `raw`：接近产品原始日志的补充信息。


平台按选手提交的 artifact `event_id` 计分；PCAP/XML 的分析结论必须转换为 `evidence.csv`、`timeline.csv` 和 `attack_graph.json` 中的 evidence 引用。

`artifacts/artifact_event_index.csv` 是 artifact 事件总索引，覆盖 PCAP packet 和 Windows XML event。该索引只提供定位和引用关系，不代表答案。
