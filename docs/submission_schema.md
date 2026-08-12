**提交格式**

最终 ZIP 可直接包含五个核心文件，或只额外包一层目录且五个文件必须直接位于该目录内；不允许更深层级。所有 JSON 字段和 CSV 表头都采用严格校验：不得缺字段、增加字段或调整表头顺序。

**1. manifest.json**

```json
{
  "team_id": "team01",
  "schema_version": "1.0",
  "created_at": "2026-07-10T16:00:00+08:00"
}
```

- `team_id` 必须与上传 token 对应的队伍编号完全一致。
- `created_at` 必须是带时区的 ISO 8601 时间。

**2. evidence.csv**

严格表头：

```csv
evidence_id,event_id,stage
E001,waf-20260706-000001,recon
```

- `evidence_id` 是队伍自定义且唯一的证据编号。
- `event_id` 必须来自公开日志或 artifact 索引；同一个 `event_id` 只能提交一次。
- `stage` 必须取自 `docs/stage_enum.md`。
- PCAP 事件通过 `artifacts/pcap/pcap_manifest.csv` 引用；Windows XML 事件使用 `EventData/ArtifactEventId`。

**3. timeline.csv**

严格表头：

```csv
step,stage,time_start,time_end,evidence_ids
1,recon,2026-07-05T20:43:31+08:00,2026-07-05T20:43:31+08:00,E001
```

- `step` 必须从 1 开始连续编号，且对应时间不得倒序。
- 每一行只表示一个可由所引证据确认的攻击步骤。
- `time_start`、`time_end` 必须带时区，且开始时间不得晚于结束时间。
- `evidence_ids` 使用分号分隔，必须引用 `evidence.csv` 中存在的证据编号。

**4. attack_graph.json**

顶层字段严格为：

```json
{
  "schema_version": "1.0",
  "incident_id": "build-final-2026",
  "nodes": [],
  "edges": []
}
```

节点字段严格为 `id`、`type`、`label`。`id` 必须采用 `type:value` 形式，前缀与 `type` 一致；节点类型见选手手册。

边字段严格为：

```json
{
  "id": "edge-sample-001",
  "from": "ip:sample",
  "to": "host:sample",
  "action": "scan",
  "stage": "recon",
  "time_start": "2026-07-05T20:43:31+08:00",
  "time_end": "2026-07-05T20:43:31+08:00",
  "evidence_ids": ["E001"]
}
```

`from`、`to` 必须引用本图节点；`action` 见 `docs/action_enum.md`；边必须引用非空且真实存在的 `evidence_ids`。

也可以先维护两个辅助 CSV：

```csv
node_id,type,label
ip:sample,ip,sample
host:sample,host,sample
```

```csv
edge_id,from,to,action,stage,time_start,time_end,evidence_ids
edge-sample-001,ip:sample,host:sample,scan,recon,2026-07-05T20:43:31+08:00,2026-07-05T20:43:31+08:00,E001
```

生成命令：

```bash
python3 tools/build_attack_graph.py graph_nodes.csv graph_edges.csv attack_graph.json
```

**5. ioc.csv**

严格表头：

```csv
type,value,first_seen,last_seen,related_asset,evidence_ids
ip,192.0.2.234,2026-07-05T20:43:31+08:00,2026-07-05T20:43:31+08:00,edge-fw-01,E001
```

- `type` 只能为 `ip`、`domain`、`file`、`account`、`token`、`command`。
- 相同 `type,value` 只能提交一次。
- `related_asset` 有多个值时使用分号分隔。
- 时间范围、关联资产和证据引用均参与 IOC 评分。

正式提交中没有 `note`、`summary`、`confidence`、`technique`、`attrs` 或 `critical_path` 字段。
