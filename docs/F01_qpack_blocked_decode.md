# F01: QPACK Blocked Decode 的通俗解释与仓库落点

## 先用一句人话说清楚

F01 不是“服务端不会解这个 HEADERS”。

真正的问题是：客户端把一大段 `HEADERS` 字节发进来后，服务端很快就对 QUIC 流控说“这些字节我已经吃掉了，可以继续给我更多”；但与此同时，这些字节其实又被 HTTP/3 的 QPACK 解码器搬进了另一个堆缓冲里继续存着，而且这个缓冲在 blocked 状态下不会很快释放。

所以它像这样：

1. QUIC 流控账本上，这些字节已经“消费完成”。
2. 真实进程内存里，这些字节其实还活着。
3. 对端因此还能继续发更多同类字节。
4. 结果就是连接不一定马上报错，但服务端 RSS/PSS 会持续涨。

## 从 0 开始理解：这些概念分别是什么

### 1. QUIC 流是什么

可以把一条 QUIC 连接理解成一条高速公路，里面能并行跑很多条“子通道”，每条子通道就是一个 stream。

- request stream：承载某一个 HTTP 请求/响应
- control stream：承载 HTTP/3 的控制信息
- QPACK encoder/decoder stream：承载动态表更新和确认

### 2. HTTP/3 的 HEADERS 里装的不是明文头

HTTP/3 里，请求头不是直接明文写到 request stream 上，而是先变成一个 `HEADERS` frame。

这个 `HEADERS` frame 的 payload 里放的是一段 QPACK 压缩后的 `header block`。也就是说，服务端收到的不是直接可读的 `:method: GET`，而是一段“要交给 QPACK 解压”的字节。

### 3. QPACK 为什么会 blocked

QPACK 允许头块引用“动态表”里的条目，这样压缩率更高。

但如果请求头说“我要引用动态表里的第 1 条”，而服务端此时还没从 QPACK encoder stream 上收到那条动态表插入，那么它就没法立刻继续解码。这个状态就叫 blocked decode。

这不是解码失败，而是“现在先等等，等字典到了再继续”。

### 4. quiche 这里的数据流怎么走

可以把 quiche 这条链路想成 4 个环节：

1. QUIC request stream 收到一段字节。
2. HTTP/3 frame decoder 认出这是一段 `HEADERS` payload。
3. 这段 payload 立刻被喂给 QPACK progressive decoder。
4. `QuicSpdyStream` 随后把这段字节记成“已消费”，归还 QUIC 流控窗口。

正常情况下，这样做没问题，因为字节会很快被真正解开，变成 header list。

## F01 的根因

问题只在 blocked decode 时出现。

当 QPACK decoder 发现“这个头块依赖的动态表项还没到”后，它不会继续真正解码，而是把后续收到的原始 payload 字节追加到它自己的堆缓冲里。可以把这个缓冲理解成：

- 不是 QUIC sequencer 的收包缓冲
- 不是 HTTP/3 frame decoder 的统一 payload 缓冲
- 而是 QPACK blocked 路径专门保留的一份“以后再说”的原始字节副本

于是，F01 变成了一个“双重真相”：

- 对 QUIC 流控来说：这段字节已经被应用消费，可以返还窗口
- 对进程内存来说：这段字节仍然在 QPACK decoder 的堆里活着

这就是为什么它会表现成内存型 DoS，而不是一个立即断开连接的协议错误。

## 被占住的内存里到底存的是什么

这里存的不是已经解析好的 header name/value 列表，至少在 blocked 期间主要不是。

主要存的是：

1. `HEADERS` frame payload 里的原始 QPACK header block 字节
2. 这些字节在 blocked 状态下被追加进 decoder 内部 buffer 的副本
3. 少量伴随这条 blocked stream 的状态对象

所以从攻击视角看，最值钱的点不是“让服务端做很多 CPU 解码”，而是“让服务端把我发来的原始字节长期存在堆里”。

## 为什么常见 limit 兜不住

### 1. QUIC 流控兜不住

QUIC 流控限制的是“还有多少未消费字节挂在流上”。

一旦实现调用了“已消费”，窗口就会返还。它不关心这些字节是不是又被应用层复制到了另一个堆对象里。

### 2. HTTP/3 的 buffered-frame 上限兜不住

`HEADERS` 在这里是流式喂给上层 visitor 的，不是像某些控制帧一样先整体缓冲再统一解析，所以不会吃到那个 buffered-frame payload 限制。

### 3. blocked streams 上限也兜不住单个头块大小

`QPACK_BLOCKED_STREAMS = 100` 只能限制“同时最多多少条 blocked stream”。

它不限制“每条 blocked stream 最多缓存多少原始 HEADERS 字节”。

## 这个仓库里怎么构造

### 当前结论

- `gen_h3_testcase` 可以构造 F01
- 当前 `gen_testcase` 不能直接构造 F01

### 为什么 `gen_h3_testcase` 可以

因为它能直接下发 HTTP/3/H3I 动作：

- 打开 control stream
- 发合法 `SETTINGS`
- 在 request stream 上直接发原始 `StreamBytes`
- 把一个 `HEADERS` frame 切成多段分片
- 故意不发 QPACK encoder stream 的动态表插入

这正是 F01 需要的最细粒度控制。

### 为什么 `gen_testcase` 现在不行

`gen_testcase` 现在生成的是 QUIC 传输层 frame 组合，适合做：

- `PING`
- `CRYPTO`
- `NEW_CONNECTION_ID`
- `PATH_CHALLENGE`

它还没有 HTTP/3/QPACK 这一层的语义，也不会帮你创建：

- HTTP/3 control stream
- request stream 上的 `HEADERS` frame
- QPACK 前缀与后续 payload 分片

所以如果要让 `gen_testcase` 也能生 F01，必须先给它扩出一层 H3 action 或 raw stream-bytes 模型。

## 这个仓库里已经加了哪些 F01 样例

现在有两类 F01 种子：

1. 最小复现：
   `fuzzers/my_h3_fuzzer/corpus-nor/h3_qpack_blocked_decode_testcase`
2. 放大观测：
   `fuzzers/my_h3_fuzzer/corpus-nor/h3_qpack_blocked_decode_amplified_testcase`

第二个种子会在同一条连接上打开多条 request stream，并给每条 blocked stream 挂上一段更大的原始 HEADERS payload，更适合配合内存观测看 RSS/PSS 的持续增长。

## mem 检测器现在能不能发现这类问题

这次修改后，答案是“可以更接近 F01 真实症状地发现并报告”。

`MemObserver` 现在会采集：

- `VmRSS`
- `RssAnon`
- `Pss`
- `Private_Dirty`
- `fd_count`
- 以及原本的可写映射总量

其中：

- `before_mem` / `after_mem` / `initial_mem` 的主判定指标改为 `VmRSS`
- 差分日志会同时打印 `VmRSS/RssAnon/Pss/Private_Dirty/fd_count`

这意味着它不再只盯着 `/proc/<pid>/maps` 的可写映射大小，而是能看到 F01 这种“堆里真的留住了字节”的现象。

### 还有什么不是 MemObserver 管的

`cpu_pct` 仍然属于 `CPUUsageObserver` 的职责，不属于 `MemObserver`。不过 `check_corpus` 和 fuzz 主流程本来就已经同时挂了 CPU observer 和 Mem observer。

## 建议怎么回放

如果你要人工确认 F01，建议优先回放这两个语料：

1. `h3_qpack_blocked_decode_testcase`
2. `h3_qpack_blocked_decode_amplified_testcase`

然后结合：

- `check_corpus`
- 服务端日志
- `MemObserver` 的差分日志

重点看 4 件事：

1. 连接没有立刻因为协议错误关闭
2. blocked request stream 长时间不返回响应
3. `VmRSS/RssAnon/Pss/Private_Dirty` 在回放后明显增长
4. 超过 blocked stream 上限后出现明确的 QPACK 相关关闭
