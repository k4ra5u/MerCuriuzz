# 第七章 QUIC Hunter 融合实施说明

## 1. 目标与适用范围

本文档用于指导后续将 QUIC Hunter 的发现与实现识别方法并入当前 `quic_pipeline`。本文档只定义预期实现方案、数据接口、判定规则和验证方法，不包含本轮代码修改。

融合目标分为两部分。

第一，将 `7.2.1` 的全网发现阶段从“解析 ZMap 回包中的纯 Version Negotiation 包”升级为 QUIC Hunter 所采用的 `Initial-VN` 思路，即发送一个形态完整、但版本字段被改为保留版本号的 QUIC Initial 探针，以兼顾低状态探测与更高发现率。

第二，将 `7.2.3` 的实现识别从当前主要依赖版本序列的单一判定，升级为基于三路信号的冗余投票，包括版本序列特征、`ALPN=invalid` 触发的 `CONNECTION_CLOSE` 错误消息，以及成功握手后 TLS 扩展顺序与 QUIC transport parameter 顺序。

主要参考资料如下。

- QUIC Hunter 论文：<https://arxiv.org/pdf/2308.15841>
- QUIC Hunter 公开仓库：<https://github.com/quic-hunter/libraries>

## 2. 当前流水线现状

当前项目中的四阶段流水线已经基本对应第七章的方法框架。

### 2.1 阶段一：版本协商探测与初步实现识别

当前阶段一位于 [identify.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/identify.rs)。它从 ZMap 的 UDP CSV 输出中读取 `saddr`、`sport`、`classification`、`data` 与 `success` 等字段，对成功的 UDP 回包执行 QUIC Version Negotiation 解析，并输出：

- `IP`
- `Port`
- `versions`
- `quic_libs`
- `remark`

现有实现的核心特点如下。

- 只接受 `version=0x00000000` 的 Version Negotiation 包。
- 通过版本序列与本地签名库匹配来给出实现候选。
- 若回包是其他 Long Header 但不是 Version Negotiation，则会被丢弃，不计入 QUIC 可达。

现有限制也很明确。

- 当服务端会先完整解析 Initial，再检查版本字段时，当前阶段一会漏检。
- 当前阶段一没有显式保存“发现证据类型”，因此无法区分“通过 VN 发现”和“通过其他 Long Header 发现”。
- 当前阶段一的实现识别只依赖版本序列，鲁棒性不足。

### 2.2 阶段二：PDNS 反查与域名候选生成

当前阶段二位于 [pdns.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/pdns.rs)。其作用是对阶段一输出的 IP 做被动 DNS 反查，生成当前域名与历史域名候选集合，并形成后续 SNI 验证的输入。

这一阶段已经满足论文中的职责要求。它的作用不是证明风险，而是为之后的 SNI 连通性验证提供尽可能合理的候选域名，以减少因缺失 SNI 造成的误失联。

### 2.3 阶段三：最小握手验证

当前阶段三位于 [pipeline.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/pipeline.rs) 与 [measure.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/measure.rs)。它会基于阶段二得到的候选域名集合，对每个目标执行最小握手验证，并在一旦握手成功后立即发送 `CONNECTION_CLOSE`。

现有实现已经满足以下原则。

- 只验证“是否可以完成最小握手”。
- 使用 SNI 候选列表逐个尝试，遇到成功即停止。
- 成功后立即关闭连接，不发送额外应用层负载。

现有限制如下。

- `QuicStruct` 当前固定配置了一组 ALPN，不支持按测量目的切换为 `invalid`。
- 阶段三没有保存 `CONNECTION_CLOSE` 原始错误消息。
- 阶段三没有从握手报文中恢复 TLS 扩展顺序和 QUIC transport parameter 顺序。

### 2.4 阶段四：低影响风险探针

当前阶段四位于 [measure.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/measure.rs)。它在已确认可连接的目标上执行受限规模的探针，并输出按阶段组织的风险证据。

该阶段与本文档的主要交集不在探针本身，而在于后续应能读取新增的实现识别结果，以支持“风险信号主要集中在哪些实现和部署中”的分析。

## 3. `7.2.1` 融合方案：从纯 VN 解析升级为 `Initial-VN`

### 3.1 设计目标

阶段一的目标仍然是以低影响方式在全网范围识别 QUIC 可达目标，但探针选择从“简化保留版本探针”升级为“合法 Initial 形状 + 保留版本号”的 `Initial-VN` 探针。

这里的核心理由是，部分实现并不会在读到版本字段后立即返回 Version Negotiation，而是先尝试完整解析 Initial。如果探针不具备合法 Initial 的基本形状，这类实现就不会响应，从而被漏检。

### 3.2 探针来源与默认值

后续实现时，阶段一默认使用 QUIC Hunter 公开仓库中的完整 Initial 探针样本，并将版本字段设置为保留版本号 `0x1a1a1a1a`。

建议将后续实际使用的探针文件固定存放在：

- `fuzzers/quic_pipeline_tui/assets/initial_vn_1a1a1a1a.pkt`

该探针应满足以下条件。

- 它来自一次真实 QUIC Initial 发送字节，而不是人工拼接的极简保留版本包。
- 除版本字段外，其余 Initial 形状保持不变。
- 默认保留版本号为 `0x1a1a1a1a`，不使用 `0x0a0a0a0a` 等其他值，以便统一实验口径。

### 3.3 阶段一回包分类规则

阶段一对每个成功的 UDP 回包执行如下分类。

#### 3.3.1 `quic-vn`

满足以下全部条件时，判定为 `quic-vn`。

- 回包为 Long Header。
- 版本字段为 `0x00000000`。
- 回包中的目标连接 ID 与原探针源连接 ID 匹配。
- 回包中的源连接 ID 与原探针目标连接 ID 匹配。
- 版本列表区域长度为 4 字节对齐，且至少包含一个版本号。

对 `quic-vn`，应提取服务器宣告的版本列表，并将其作为 `observed_versions`。

#### 3.3.2 `quic-lh`

满足以下全部条件时，判定为 `quic-lh`。

- 回包为 Long Header。
- 回包版本字段与探针版本字段相同，即仍为 `0x1a1a1a1a`。
- 回包中的目标连接 ID 与原探针源连接 ID 匹配。

对 `quic-lh`，说明目标接受了合法 Initial 的基本形状并对该保留版本做出了 QUIC 层响应。此时应将该目标同样视为 `supports_quic=true`。但 `quic-lh` 不代表获得了服务端支持版本集合，因此其 `observed_versions` 只记录回包中的版本字段值，不参与版本序列指纹匹配。

#### 3.3.3 `invalid`

以下情况统一判定为 `invalid`。

- 报文长度不足。
- 不是 Long Header。
- CID 对应关系不成立。
- `quic-vn` 的版本列表区长度异常。
- 其他无法被解释为 QUIC 探针响应的情况。

### 3.4 CID 校验规则

后续实现必须显式保留并使用“原探针字节”参与离线解析，不能只看回包本身。原因是 CID 对应关系是区分真实 QUIC 响应和普通 UDP 噪声的关键证据。

校验规则固定如下。

- 对 `quic-vn`，回包的 DCID 必须等于原探针的 SCID，回包的 SCID 必须等于原探针的 DCID。
- 对 `quic-lh`，至少要求回包的 DCID 等于原探针的 SCID；若实现需要更严格判定，可同时校验 SCID 长度和取值，但不得放宽上述最低要求。

### 3.5 阶段一输出接口

阶段一保留现有输出文件 `*.versions.csv`，但将其扩展为新表头：

`IP,Port,versions,quic_libs,remark,phase1_class,probe_version,cid_valid,supports_quic`

其中字段含义固定如下。

- `versions`：字符串形式的 `observed_versions`，使用空格分隔的十六进制版本号。
- `quic_libs`：当前版本序列指纹给出的实现候选；仅在 `phase1_class=quic-vn` 时参与判定。
- `remark`：当前版本特征匹配的备注信息。
- `phase1_class`：`quic-vn`、`quic-lh` 或 `invalid`。
- `probe_version`：默认固定为 `0x1a1a1a1a`。
- `cid_valid`：`true` 或 `false`。
- `supports_quic`：`true` 或 `false`。

这里保留 `versions`、`quic_libs` 和 `remark`，是为了与现有阶段二、阶段三代码接口尽量兼容。实现时应将 `versions` 视为 `observed_versions` 的兼容字段。

### 3.6 阶段一对实现识别的使用约束

阶段一中的版本特征只能作为“快速初筛信号”。

具体规则固定如下。

- `phase1_class=quic-vn` 时，允许对 `versions` 执行现有签名匹配，输出 `version_fp`。
- `phase1_class=quic-lh` 时，不执行版本序列签名匹配，`version_fp` 为空。
- `phase1_class=invalid` 时，该目标不进入后续阶段。

## 4. `7.2.3` 融合方案：三路信号冗余投票

### 4.1 总体原则

后续实现中，实现识别不再依赖单一来源，而是输出三路独立信号。

- `signals.version_fp`
- `signals.alpn_error_fp`
- `signals.tp_order_fp`

然后再汇总为：

- `vote_result`
- `confidence`
- `collision_note`

后续阶段四和结果分析以 `vote_result` 作为默认实现标签，以 `confidence` 作为可信度说明，以 `collision_note` 记录冲突与重试信息。

### 4.2 新增中间输出文件

后续实现时新增一个单独的实现识别输出文件：

- `*.identify.jsonl`

推荐每行结构如下。

```json
{
  "_row": 1,
  "IP": "1.2.3.4",
  "Port": 443,
  "selected_domain": "example.com",
  "phase1_class": "quic-vn",
  "signals": {
    "version_fp": "quic-go",
    "alpn_error_fp": "quinn",
    "tp_order_fp": "quinn"
  },
  "vote_result": "quinn",
  "confidence": "high",
  "collision_note": null
}
```

阶段四不修改现有风险输出格式，但应在读取 `connect_output` 的同时读取 `identify_output`，将实现标签与风险信号聚合到同一分析视图中。

### 4.3 信号一：版本序列特征

`signals.version_fp` 继续复用 [identify.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/identify.rs) 中的现有版本签名库作为种子。

其角色固定为“快速初筛”，不再作为最终实现判定的唯一依据。

输出规则如下。

- 若版本序列唯一命中一个实现，输出该实现名。
- 若命中多个实现，输出以 `|` 连接的候选集合，并在后续投票时视为弱信号。
- 若未命中，输出空值。

### 4.4 信号二：`ALPN=invalid` 触发的错误消息

#### 4.4.1 触发方式

在阶段三完成常规 `h3` 最小握手验证后，新增一次轻量的 `invalid ALPN` 子探测。

规则固定如下。

- 优先使用阶段三已验证成功的 `selected_domain` 作为 SNI。
- 若无 `selected_domain`，但无 SNI 握手已成功，则允许无 SNI 发送。
- ALPN 列表仅包含一个值：`invalid`。
- 一旦观察到服务端的 `CONNECTION_CLOSE` 或握手失败终止，即停止交互。

这里不发送 HTTP 请求，不进入应用层负载交换。

#### 4.4.2 需要新增的 `QuicStruct` 能力

当前 [quic_conn.rs](/home/john/quic-fuzz/MerCuriuzz/libafl-modules/src/inputstruct/quic_conn.rs) 在配置阶段写死了多个 ALPN。后续实现必须新增以下能力。

- `QuicStruct` 可按调用者传入的 ALPN 列表构造连接。
- 调用者可明确选择 `["h3"]` 或 `["invalid"]`。
- 可读取并导出服务端返回的 `peer_error` 信息，包括：
  - `is_app`
  - `error_code`
  - `frame_type`
  - `reason`

#### 4.4.3 错误消息指纹表

后续实现以 QUIC Hunter 仓库中的 `classify_alpn.py` 为种子构造映射表。建议将该映射表固化为本地静态配置，初始至少覆盖以下消息。

- quiche 系：`CRYPTO_ERROR ... no application protocol`
- Akamai 系：`PROTOCOL_VIOLATION ... No known ALPN provided by client` 或等价内部错误
- lsquic 系：`no suitable application protocol` 或 `TLS alert 80`
- quant：`PTLS error 120 (NO_APPLICATION_PROTOCOL)`
- kwik：`unsupported application protocol: invalid`
- aioquic：`No common ALPN protocols`
- nginx：`handshake failed`
- quinn：`peer doesn't support any known protocol`
- mvfst：`Unable to negotiate ALPN`

实现时必须同时保存原始 `reason` 字符串，分类表只负责生成 `signals.alpn_error_fp`，原文不能丢失。

### 4.5 信号三：TLS 扩展顺序与 transport parameter 顺序

#### 4.5.1 触发方式

对阶段三常规 `h3` 最小握手成功的目标，新增一次“顺序指纹采集”。

规则固定如下。

- 只做到握手成功并接收服务端的加密握手消息。
- 不发送 HTTP/3 GET。
- 一旦所需顺序信息采集完成，即立即关闭连接。

#### 4.5.2 采集方法

当前 `quiche` 暴露的是已经解析后的 transport parameters，无法保留原始发送顺序。因此，后续实现不得直接依赖 `peer_transport_params` 的结构化字段顺序，而应在 [quic_conn.rs](/home/john/quic-fuzz/MerCuriuzz/libafl-modules/src/inputstruct/quic_conn.rs) 中新增对握手期 CRYPTO 数据的观测与解析。

具体方法固定如下。

1. 在握手阶段收集服务端 Initial/Handshake 空间中的 CRYPTO frame。
2. 按 offset 重组 TLS 握手字节流。
3. 解析 `ServerHello`，提取其扩展列表的线序。
4. 在线序结果中仅保留：
   - `51`：`key_share`
   - `43`：`supported_versions`
5. 解析 `EncryptedExtensions`，定位 QUIC transport parameter 扩展：
   - RFC 9000 正式值 `57`
   - 兼容保留 `65445`
6. 对 transport parameter 原始字节按 QUIC varint 顺序解析，只记录参数类型顺序，不对类型排序。

#### 4.5.3 `signals.tp_order_fp` 的生成

后续实现以 QUIC Hunter 仓库中的 `classify_tlstp.py` 和 `tlstp_backend.py` 为种子，生成如下指纹格式：

`ServerHello扩展顺序_TransportParameter顺序`

例如：

- `51-43_0x4-0x6-0x7-0x8-0x0-0xf`
- `43-51_0x0-0x2-0xf-0x6-0x7-0x4-0x8`

初始实现时，可直接采用 QUIC Hunter 已公开的映射表作为基础种子，并允许在本地实验环境中增量补充。

### 4.6 投票规则

投票规则固定为以下优先级，不留给后续实现者再做选择。

#### 4.6.1 优先级

优先级从高到低为：

1. `tp_order_fp`
2. `alpn_error_fp`
3. `version_fp`

#### 4.6.2 一致性规则

- 若 `tp_order_fp` 唯一命中，且其他已存在信号与其一致或为空，则 `vote_result=tp_order_fp`，`confidence=high`。
- 若 `tp_order_fp` 唯一命中，但与 `alpn_error_fp` 或 `version_fp` 冲突，则 `vote_result=tp_order_fp`，`confidence=medium`，并记录 `collision_note`。
- 若没有 `tp_order_fp`，但 `alpn_error_fp` 唯一命中，则 `vote_result=alpn_error_fp`。若 `version_fp` 同时一致，则 `confidence=medium`；否则仍为 `medium`，但备注“仅由 ALPN 错误消息支持”。
- 若只有 `version_fp` 可用，则 `vote_result=version_fp`，`confidence=low`。
- 若多个信号均为空，或冲突无法消解，则 `vote_result=unknown`，`confidence=low`。

### 4.7 随机化顺序的碰撞消解

对已知 transport parameter 顺序随机化或可置换实现，必须执行重复握手复测。

复测规则固定如下。

- 首次握手后，如 `tp_order_fp` 命中“随机化实现/固定实现共享模式”的碰撞集合，则以相同 SNI、相同 ALPN=`h3` 再执行 2 次握手，总计 3 次。
- 若 3 次中观察到同一碰撞族内出现至少 2 种顺序，则判定为随机化实现，`confidence=medium`。
- 若 3 次中顺序保持一致，则判定为固定顺序实现，`confidence=high`。
- 若 3 次均未拿到完整顺序信息，则保留原有较弱结论，并在 `collision_note` 中写明“replay_incomplete”。

实现时，第一版至少要覆盖 QUIC Hunter 文中明确提到的顺序碰撞场景，不能把所有碰撞都直接归为 `unknown`。

## 5. 代码改动边界

后续实现时，代码改动范围原则上限定在以下位置。

- [identify.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/identify.rs)
- [pipeline.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/pipeline.rs)
- [measure.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/measure.rs)
- [common.rs](/home/john/quic-fuzz/MerCuriuzz/fuzzers/quic_pipeline_tui/src/common.rs)
- [quic_conn.rs](/home/john/quic-fuzz/MerCuriuzz/libafl-modules/src/inputstruct/quic_conn.rs)

其中关键新增能力只有两类，且必须优先实现。

### 5.1 可配置 ALPN

`QuicStruct` 不得继续仅使用固定 ALPN 列表。后续接口应允许调用者显式传入：

- `["h3"]`
- `["invalid"]`
- 未来扩展值

### 5.2 握手原始观测接口

必须新增能输出以下信息的观测接口。

- `CONNECTION_CLOSE` 的错误码与 reason phrase
- `ServerHello` 扩展顺序
- `EncryptedExtensions` 中 QUIC transport parameter 的原始顺序

仅依赖当前结构化后的参数对象，不足以复现 QUIC Hunter 方法。

## 6. 后续验证计划

### 6.1 阶段一离线验证

阶段一的第一轮验证应完全离线完成，不直接上网重扫。

输入固定为：

- QUIC Hunter 的 `0x1a1a1a1a` Initial 样本
- 现有 ZMap CSV 输出

必须覆盖以下情形。

- 合法 `quic-vn`
- 合法 `quic-lh`
- CID 不匹配
- 长度异常
- 非 QUIC UDP 回包

### 6.2 实现识别验证

利用本地多实现实验环境，对以下两类交互分别做验证。

- `ALPN=invalid`
- 正常 `h3` 握手

验证目标固定如下。

- 错误消息是否稳定可复现
- TLS 扩展顺序是否能按线序恢复
- QUIC transport parameter 顺序是否能按线序恢复
- 已知随机化实现的复测规则是否有效

### 6.3 与阶段四聚合的验收要求

最终验收时，应满足以下三个条件。

- 对每个进入阶段四的目标，都能关联到一个 `vote_result`，即使其值为 `unknown`。
- 风险结果能按 `vote_result`、IP、域名和组织维度聚合。
- 论文中使用的“实现分布”和“风险集中实现”统计，均来自统一的 `identify_output` 与 `measure_output` 联合结果，而不是人工拼接。

## 7. 结论

本方案的核心不是替换现有四阶段框架，而是在保持现有发现、PDNS、SNI 验证和低影响探针框架不变的前提下，对“发现证据”和“实现识别证据”两部分做增强。

阶段一通过 `Initial-VN` 提高 QUIC 发现率，阶段三通过 `invalid ALPN` 与 transport parameter 顺序补充实现指纹，最终以三路弱证据投票给出更稳健的实现候选。这样既与第七章的研究问题保持一致，也能自然支撑后续“风险信号集中在哪些实现和部署中”的统计分析。
