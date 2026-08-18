# 面试 QA 准备

> 文档日期：2026-08-18
> 适用岗位：后端/服务端开发
> 项目：加密文件系统（Go · 不可信存储）
> 简历定位：辅助项目（2-3 行）

## 使用说明

每个答案准备 **30 秒口述版** + **3 分钟展开版**。面试官追问时给展开版，不追问就停在 30 秒版。

支撑材料：
- `docs/benchmark.md` — 并发基准数据
- `docs/threat-model.md` — 6 类攻击防御
- `docs/architecture-comparison.md` — vs 学城模型层对比

---

## 一、项目追问（最深，最关键）

### Q1：你说"零信任原则"，具体怎么落地的？零信任的核心是什么？

**为什么问**：零信任是流行词，区分"抄概念"还是"真理解"。

**参考答案**：

零信任核心是"永不信任，始终验证"——不对任何存储/网络组件默认信任。本项目的落地：

1. **存储层零信任**：Datastore 视为完全不可信，能任意读写/篡改。所有数据加密 + HMAC，不依赖服务端鉴权
2. **密钥层零信任**：密钥不出客户端，服务端永远拿不到明文密钥
3. **权限层零信任**：撤销不靠删权限条目（服务端可被绕过），靠密码学层全密钥重生——即使存储全部泄露，被撤销用户也无法解新数据
4. **完整性零信任**：HMAC 输入绑 chunk UUID，防 swap；metadata 独立 HMAC，防 rollback 检测

对比传统方案：Dropbox/学城等服务端可信模型，撤销靠服务端权限检查，服务端被攻破就全暴露。本项目即使服务端被攻破，密码学层仍能保护。

---

### Q2：前向保密具体怎么实现的？为什么叫"前向"？

**为什么问**：核心差异化，必问。

**参考答案**：

"前向"指**未来的数据**——撤销后产生的新数据，被撤销用户即使持有旧密钥也无法解密。

实现流程（`client/revoke.go`）：

1. BFS 遍历共享树，找出所有下游被撤销用户
2. 生成全新 `fileEncKey` / `fileHMACKey` / `metadataEncKey` / `metadataHMACKey`
3. 用新密钥重新加密所有 chunk（不是只加密新 chunk）
4. 生成新 metadata UUID（旧 metadata 删除）
5. 更新保留用户的 FileView 指向新 metadata
6. 删除旧 chunk 链 + 旧 ShareList

关键：**全密钥重生 + 删旧 chunk**。如果只换新密钥不删旧 chunk，被撤销用户用旧 key 仍能解旧 chunk 副本——前向保密破坏。

这是 vs Dropbox/学城的核心差异：它们服务端持明文，撤销只删权限条目；本项目密码学层彻底重置。

测试支撑：`TestRevokedUserOldKeysFailOnNewChunks`——验证撤销后用旧 fileEncKey 解新 chunk 返回 HMAC mismatch。

---

### Q3：100 并发 0 chunk 丢失怎么测的？为什么是 0 而不是有冲突？

**为什么问**：验证数字真实性，看是否理解并发本质。

**参考答案**：

测试：`TestConcurrentAppend_100`——100 goroutine 各 append 1 byte 到同一文件，最终断言文件长度 = init + 100。

0 冲突的原因是设计选择：`AppendToFile` 用 per-metadataUUID mutex 包住 LoadMeta + SaveChunk + SaveMeta 整个关键段，让同一文件的 append 严格串行化。

这不是"高并发优化"，而是"场景适配"——append-only 链表追加本质就是串行操作（每个 append 要更新 TailPtr），强行并行反而引发 chunk 链表断裂。

对比学城的 stepVersion OT：学城是结构化编辑场景（insert/replace/remove/mark），冲突率 2% 需要 rebase；我是字节 append，0 冲突 + 串行化更适合。

benchmark 数据：100 并发 14.2μs/op（比顺序 18.5μs 还快，Go scheduler 利用 12 核并行处理不同文件）。

---

### Q4：userlib fatal 怎么发现的？调试过程？

**为什么问**：验证 TDD 价值 + 调试能力。这是简历最强钩子。

**参考答案**：

写完 100 并发测试跑第一次，直接 `fatal error: concurrent map read and map write` 崩溃。

调试过程：

1. 看堆栈定位到 `userlib.go:135` 的 `datastoreGet`——`datastoreShard[key]` map 读取
2. 看 userlib 源码：`datastore` 用 `sync.Map` 但 `getDatastoreShard` 返回的是 `map[UUID][]byte` 普通 map，不是 `sync.Map` 的原子操作
3. userlib 是课程框架不可改，只能在 client 层加锁
4. 第一版加全局 `sync.Mutex` 保护所有 Datastore 调用，测试通过
5. 但全局锁是瓶颈，第二版加 per-UUID mutex 让不同文件 append 并行

反思：第一版只加全局锁不够——append 关键段内 LoadMeta + SaveChunk + SaveMeta 三步必须原子，全局锁只保护单步，多 goroutine 仍可能读到相同 TailPtr 后互相覆盖 chunk 链表。所以 per-UUID 锁要包住整个关键段，不只是单次 Datastore 调用。

教训：**单步原子 ≠ 关键段原子**。锁的粒度要匹配关键段，不是单个操作。

---

### Q5：为什么不缓存权限？性能不会差吗？

**为什么问**：验证"模型层权衡"叙事是否真懂。

**参考答案**：

不可信存储下缓存权限有额外挑战——缓存可被攻击者篡改。学城服务端可信，缓存"无权限"条目不会被改；本项目缓存放在 Datastore 上，攻击者把"无权限"改成"有权限"就绕过权限系统。

缓存需密码学保护：缓存条目带 HMAC 签名，密钥由客户端持有。但验证 HMAC 本身要加载缓存条目 + 算 HMAC，性能收益打折。

当前实现：每次 `ResolvePermission` 全量递归加载 Directory + 验证 HMAC。深度 N 的目录树最坏 N 次 DatastoreGet + N 次解密。

升级路径：客户端本地缓存（in-memory，不带 HMAC 因为不经过不可信存储）+ 服务端变更广播失效。但多客户端本地缓存的失效一致性需要额外协调，目前单机 demo 不值得做。

这是**模型决定的代价**，不是没做缓存。

---

### Q6：metadata rollback 攻击你说"部分防御"，具体什么意思？

**为什么问**：验证对已知限制的诚实度。

**参考答案**：

不可信存储无法完全防御 rollback——攻击者把 Datastore 里的 metadata 回滚到旧版本，客户端无法区分"旧版本"和"当前版本"，因为没有 WORM（write-once-read-many）存储。

当前缓解：

1. metadata 有 Version 字段单调递增，客户端可审计版本回退
2. 旧 metadata 指向的旧 chunk 仍可解（如果未被覆盖），但访问不到新追加的内容

真正防御需要 WORM 存储或区块链式的不可篡改日志，超出项目 scope。我在 `docs/threat-model.md` 里明确写了这个已知限制——纯 rollback 攻击在不可信存储上无法完全防御，需配合版本审计或 WORM 存储。

诚实承认限制比硬撑"完全防御"可信得多。

---

### Q6.5：你的撤销机制和学城的"继承"有什么关系？

**为什么问**：验证对撤销机制本质的理解，看是否混淆了两套机制。

**参考答案**：

我的项目里**两套机制并存**，但用途不同：

1. **Directory 权限继承**（学城 12.4 模式）—— 用于权限**检查**阶段。访问文件时 `ResolvePermission` 递归向上查父目录权限，子节点默认继承父节点权限，显式权限优先于继承
2. **RevokeAccess BFS + 全密钥重生**（不可信存储模式）—— 用于权限**撤销**阶段。撤销时 BFS 遍历 `SignedShareList` 共享图找出所有下游用户，全密钥重生 + 删旧 chunk 实现前向保密

**为什么撤销不用继承？**

继承模型依赖**服务端可信**——服务端权限检查时继承链断开就拒绝访问。但我的存储是不可信的：

- 被撤销用户可能持有旧 chunk 副本 + 旧密钥
- 即使权限检查拒绝，他绕过权限系统直接用旧密钥解旧 chunk 仍然能读
- 必须密钥重生：让旧密钥失效（HMAC mismatch）
- 必须删旧 chunk：让旧密钥无数据可解（前向保密）

**继承只能"拒绝访问"，不能"让旧密钥失效"**——这是不可信存储 vs 服务端可信模型的根本差异。

学城撤销是 O(1) 删权限条目 + 缓存失效；我的撤销是 O(共享树大小) + 重新加密全部 chunk。性能差，但安全强度高——存储全部泄露，旧密钥也解不了新 chunk。

支撑材料：`docs/architecture-comparison.md` §6.4 + `client/revoke.go` + `client/directory.go`。

---

## 二、系统设计扩展

### Q7：如果让你把这个系统改成多机部署，怎么改？

**为什么问**：从单机 demo 到分布式，看架构演进思维。

**参考答案**：

三个核心改造：

**1. Datastore 持久化 + 分布式**

- in-memory Datastore 换成 Redis Cluster 或 DynamoDB
- 但要注意：分布式存储仍是"不可信"的，密码学层保护不变
- chunk UUID 作为 key 天然分布式友好，无热点

**2. 锁的分布式化**

- per-UUID mutex 换成 Redis 分布式锁（Redlock 或 etcd lease）
- 但要注意：分布式锁的延迟（10ms 级）远高于本地 mutex（μs 级），append 吞吐会下降
- 优化：乐观锁优先，冲突才上分布式锁——`stepVersion` 检测冲突，无冲突直接 CAS

**3. 鉴权 / 限流 / 通知的分布式**

- Bearer token store 从 in-memory 换 Redis
- 令牌桶从单机换 Redis 计数器
- 通知从 in-memory channel 换 Kafka/Mafka

关键约束：密码学层（加密/HMAC/密钥重生）**不变**——这些是客户端逻辑，跟部署无关。

---

### Q8：如果 QPS 上来，瓶颈在哪？

**为什么问**：性能分析能力。

**参考答案**：

三个潜在瓶颈：

**1. per-UUID mutex 串行化 append** —— 单文件吞吐上限 = 1 / append_latency ≈ 55K ops/s

- 优化：分 chunk 并行写入（chunk UUID 不同可并行）+ CAS metadata
- 但 CAS 冲突率高时退化为 retry 风暴，需要退避策略

**2. ResolvePermission 全量递归** —— 深度 N 目录树 N 次 DatastoreGet

- 优化：客户端本地缓存 `(user_id, doc_id) → permission` + 服务端变更广播失效
- 或：把权限计算下推到存储层（SQL JOIN）

**3. 全局 datastoreMu** —— 所有 Datastore 操作串行

- 这个是 userlib 限制，生产代码不会有
- 真实部署用线程安全存储，这个锁不存在

最大瓶颈是 #1，但 append-only 场景下吞吐上限已够用——除非单文件 QPS > 50K，否则不需要优化。

---

## 三、八股

### Q9：AES-CTR 为什么不用 GCM？HMAC 和 GCM 的 tag 有什么区别？

**参考答案**：

GCM 是 AEAD——加密 + 认证一体化，tag 是加密时算出来的，绑 IV + AAD + 密文。

CTR + HMAC 分离——加密算一次，HMAC 算一次，tag 绑密文 + 任意自定义输入。

本项目选 CTR + HMAC 的原因：**HMAC 输入可自定义**——我把 chunk UUID 绑进 HMAC 输入，防 chunk swap。GCM 的 tag 只绑 IV + AAD，要防 swap 得把 UUID 放 AAD，但 AAD 不加密、影响密文结构。

性能上 GCM 更快（一次 pass），但本场景密码学不是瓶颈（Datastore IO 才是），HMAC 灵活性更重要。

---

### Q10：Argon2 vs bcrypt vs PBKDF2，为什么选 Argon2？

**参考答案**：

三个都是密码派生函数（KDF），抗暴力破解。

- **PBKDF2**：最早，单纯迭代 hash，GPU 并行破解效率高
- **bcrypt**：内存硬度低，GPU 破解仍有效
- **Argon2**：2015 Password Hashing Competition 冠军，**可调内存硬度 + 并行度 + 时间**三维参数，GPU/ASIC 破解成本最高

选 Argon2 因为它是当前 NIST 推荐的抗 GPU/ASIC 最强方案。参数：16 字节输出 + 默认内存硬度（64MB）+ 1 pass。

---

### Q11：RSA-OAEP 为什么不用 RSA-PKCS1v1.5？

**参考答案**：

PKCS1v1.5 有 Bleichenbacher 攻击——通过观察解密失败模式恢复明文。

OAEP 引入随机 padding + 哈希校验，解密失败时无法区分"padding 错"和"密文错"，抗选择密文攻击（CCA2）。

本项目 RSA 用于加密 invitation 的对称密钥（HybridEncrypt），用 OAEP 是基础安全卫生。

---

### Q12：HMAC 和 AES-GCM 的 tag 在安全性上有什么本质区别？

**参考答案**：

都是 MAC，安全性都基于密码学原语。区别在**密钥隔离**：

- **AES-GCM tag**：用 AES 密钥同时加密 + 算 tag，密钥复用。如果 nonce 复用，加密和认证同时崩溃
- **HMAC tag**：独立 HMAC 密钥，与加密密钥隔离。即使 AES 密钥泄露，HMAC 仍能检测篡改

本项目 `DeriveKeys` 从 master key 派生独立的 `encKey` 和 `macKey`——密钥隔离，安全性更高。

---

## 四、行为面

### Q13：项目中遇到的最大挑战？

**参考答案**（用 userlib fatal 故事）：

最大挑战是发现并修复 userlib Datastore 的并发 fatal。

写完 100 并发测试第一次跑，直接崩溃。看堆栈是 `concurrent map read and map write`，定位到 userlib 框架库的 map 非线程安全。

第一反应是改 userlib，但 userlib 是课程框架不可改。第二反应是加全局锁，跑通了但发现 append 仍然丢 chunk——因为全局锁只保护单次 Datastore 调用，append 关键段的三步（LoadMeta + SaveChunk + SaveMeta）之间仍能被插入。

最终方案是分层锁：全局锁防 fatal + per-UUID 锁包住整个关键段。这次让我深刻理解了"锁的粒度"和"关键段原子性"的区别——单步原子不等于关键段原子。

反思：如果一开始就 TDD，这个 bug 在写第一行并发代码时就会暴露，不会留到验收阶段。后来所有新功能都先写测试。

---

### Q14：为什么做这个项目？学到了什么？

**参考答案**：

做这个项目两个动机：

1. **理解零信任存储模型**——课程作业只要求功能正确，我好奇"如果存储完全不可信，密码学层能保证什么"。所以深入做了前向保密 + 6 类攻击防御
2. **对标生产系统做工程化**——参考美团学城的 stepVersion / 权限继承 / 业务域拆分，把课程作业升级到可讲故事的程度

学到最深的不是密码学，而是**模型层权衡**——不可信存储 vs 服务端可信是根本不同的模型，决定了缓存策略、版本历史、权限执行的全部差异。这不是"功能多寡"，是"设计哲学不同"。

这个思维让我在之后看任何系统都会先问"它的信任边界在哪"——这是项目的最大收获。

---

### Q15：如果重做，你会改什么？

**参考答案**：

三个会改的：

1. **测试驱动从第一天开始**——本次改造是后补测试，发现了 userlib fatal 这种隐藏 bug。如果一开始就 TDD，bug 在引入当天就暴露
2. **持久化 Datastore 早点做**——in-memory demo 限制太多演示场景，应该早做持久化层（即使只是文件系统）
3. **权限缓存早点设计**——目前每次 `ResolvePermission` 全量递归，深度 N 目录树性能差。应该早点引入客户端缓存 + 失效广播

不会改的：

- 密码学层设计——前向保密 + 全密钥重生是核心差异化，正确
- per-UUID 锁策略——场景适配正确，不是性能瓶颈
- TDD 流程——6 类对抗测试 + benchmark 证明了价值

---

## 五、反问环节（你问面试官）

建议准备 2-3 个问题，体现深度：

1. **"贵团队的存储系统在零信任架构上有什么实践？比如缓存如何密码学保护？"** —— 把项目话题延伸到对方系统
2. **"团队在做多设备协同编辑这类场景时，OT vs CRDT 怎么选？"** —— 显示对协同编辑的理解
3. **"团队对 TDD 的实践程度？对抗性测试是否纳入 CI？"** —— 工程文化问题

---

## 准备优先级

| 优先级 | 准备方向 |
|--------|---------|
| P0 | Q1-Q6 项目追问（核心） |
| P0 | Q13 行为面（userlib fatal 故事） |
| P1 | Q9-Q12 八股（密码学基础） |
| P1 | Q7-Q8 系统设计扩展 |
| P2 | Q14-Q15 行为面（反思类） |

## 答题节奏建议

| 场景 | 答案长度 |
|------|---------|
| 首次回答（不追问） | 30 秒口述版 |
| 面试官追问细节 | 3 分钟展开版 |
| 涉及代码/数据 | 指向 docs/ 支撑材料 |

## 风险预警

| 风险 | 缓解 |
|------|------|
| 面试官问"高并发"硬指标 | 诚实回答"100 并发"是测试场景，不是生产 QPS；项目定位是辅助项目 |
| 面试官问"分布式部署"经验 | 诚实回答"单机 demo，分布式是演进路径"；能讲清改造方案即可 |
| 面试官深挖"零信任"行业标准 | 诚实回答"项目层面落地，未对标 NIST 800-207 等标准" |
| 面试官问"生产用户量" | 诚实回答"无生产用户，课程项目+工程化改造" |

诚实 > 硬撑。承认边界比被打脸好。
