**正式证据素材说明**

本目录提供非 CSV/JSONL 类型的正式调查素材。

`pcap/edge_trace_20260706.pcap` 是标准 PCAP 文件。`pcap/pcap_manifest.csv` 是全量 packet 到 `event_id` 的映射表，用于把你们在 PCAP 中确认的包引用到提交文件里。

`windows_event_exports/*.evtx.xml` 是 Windows Event Log 的 XML 导出版。每条 XML 事件的 `EventData` 中包含 `ArtifactEventId`，该值可直接作为 `evidence.csv` 的 `event_id` 提交。

`artifact_event_index.csv` 是 artifact 事件总索引，覆盖 PCAP packet 和 Windows XML event。
