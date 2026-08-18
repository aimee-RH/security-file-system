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

### Q16：你怎么用 AI 协作开发？

**为什么问**：2026 秋招后端岗普遍期待 AI 协作能力。考察是否真有方法论，不是工具堆砌。

**参考答案（30 秒口述版）**：

> 我用 Claude Code 协作，核心是长任务 spec + TDD 工作流。把"打磨简历项目"拆成 SPEC 文档，每个故事先写失败测试（红），再最小实现通过（绿），最后写文档（重构）。这次简历打磨用了 `/long-task-spec-to-pr` skill——它强制我在动手前读完文档、扫完代码、列出测试接缝、生成执行计划，用户确认后才进实现阶段。

**展开版（被追问时讲）**：

长任务 spec 是一个三件套：EXECUTION_PLAN + QUESTIONS + FINAL_REPORT。

**为什么这么做**：AI 协作最大的坑不是代码错，是**上下文丢失**。一个长任务跨多轮对话，AI 容易忘之前讨论过什么、决策了什么。三件套就是把"决策"和"未决项"落文件，跨轮恢复时不丢。

- **EXECUTION_PLAN** 记录批次拆分 + 接缝清单 + 进度追踪表。这次简历打磨拆了 3 个故事、9 个 task，每个 task 有 PENDING/DONE/WAITING_CONFIRMATION 状态
- **QUESTIONS** 记录所有不明确点，用稳定 ID（Q-001、Q-002）+ 状态机（OPEN/ACTION_PENDING/RESOLVED/DEFERRED）。比如这次有 Q-001 仓库改造策略、Q-002 批次粒度等，全部 RESOLVED
- **FINAL_REPORT** 是交付报告，含功能清单、测试覆盖、review 修复记录、上线 checklist

核心原则：**不靠脑子记，必须落文件**。

**追问"接缝先行"时**：

接缝是"在哪些公共边界测"。比如这次并发基准故事，我列出 9 个测试接缝：`TestConcurrentAppend_N` 验证 N 并发不丢 chunk、`TestConcurrentAppend_NoDeadlock` 验证无死锁、`TestConflictRateCurve` 验证冲突率曲线等。

为什么先列接缝：TDD 容易写成"测代码内部实现"，但好的测试应该测**公共边界行为**。先把接缝列出来，AI 写测试时不会去 mock 内部协作者或测私有方法——这是 TDD 反模式。

**追问"发现 bug 后怎么处理"时**（最强故事）：

这是 AI 协作最大的价值——**让测试驱动 bug 发现**。

发现 fatal 后，按长任务 spec 的流程：
1. 看堆栈定位到 `userlib.go:135`
2. 看 userlib 源码：`datastore` 用 `sync.Map` 但 `getDatastoreShard` 返回普通 map，非线程安全
3. userlib 是课程框架不可改，只能在 client 层加锁
4. 第一版加全局 `sync.Mutex`——测试通过，但发现 append 仍丢 chunk
5. 反思：全局锁只保护单次 Datastore 调用，append 关键段三步（LoadMeta + SaveChunk + SaveMeta）之间仍能被插入
6. 第二版加 per-UUID mutex 包住整个关键段，跑通

这个过程体现的是**单步原子 ≠ 关键段原子**——锁的粒度要匹配关键段，不是单个操作。AI 协作帮我快速试错，每次失败都有具体堆栈可定位。

**追问"和传统开发区别"时**：

三个本质区别：

1. **测试驱动 vs 代码驱动**：传统开发先写代码再补测试，测试经常漏关键路径。AI 协作是 spec → 接缝 → 测试 → 实现，测试先于代码存在，覆盖度更可控
2. **文档驱动 vs 脑子记**：传统开发决策散落在聊天记录/脑子里，跨天就忘。三件套强制落文件，跨轮恢复时不丢
3. **对抗性测试敢于写**：传统开发怕测试难写就跳过。AI 协作让 AI 先写测试框架，我填充关键断言——6 类攻击测试这种对抗性测试，以前根本不会写，现在每个安全声明都有契约

关键体感：AI 协作最大价值不是写代码快，是**让我敢于写对抗性测试**。这次发现 userlib fatal 就是测试驱动的——如果先写代码再补测试，这个 bug 永远不会暴露。

**支撑材料**：
- `docs/2026-08-17-resume-polish/SPEC.md` — TDD spec
- `docs/2026-08-14-cs161工程化改造/EXECUTION_PLAN.md` + `QUESTIONS.md` + `FINAL_REPORT.md` — 三件套
- `client/store.go:20-24` — ponytail 注释记录 userlib fatal 修复
- `client/threat_model_test.go` — 6 类对抗性测试

**注意事项**：
- 不要硬背术语——"长任务 spec"、"三件套"、"接缝先行"是真实用的，自然讲
- 用具体例子——userlib fatal 故事是最强素材，有完整调试链
- 体现反思——"单步原子 ≠ 关键段原子"是 AI 协作中真学到的，不是抄来的
- 避免浮夸——不说"AI 让我 10x 效率"，说"让我敢于写对抗性测试"

---

### Q17：你说"项目级 CLAUDE.md 沉淀路径白名单与编码规范"，具体怎么做的？和直接写 prompt 有什么区别？

**为什么问**：验证你是否真懂 AI 编码规范工程化，还是抄概念。

**参考答案**：

CLAUDE.md 是项目级 AI 行为规则入口，跟直接写 prompt 的区别在 3 个维度：

**1. 加载机制**：CLAUDE.md 在 Claude Code 启动时自动加载到上下文，不用每次 prompt 重复写。生产项目（如 insurance_mall）进一步用 `.agent-harness/rules/` 配 paths frontmatter 按文件类型触发——处理 `.java` 自动加载 java-coding-standards，处理 `src/test/` 自动加载 testing-standards，避免一次性塞满上下文。

我的项目简化版：CLAUDE.md 里定义了 issue tracker 路径约定、triage labels、domain docs 布局。AI 协作时不需要我每次说"放在 .scratch/<feature>/ 下"——规则在 CLAUDE.md 里，AI 自动遵守。

**2. 规则可执行性**：CLAUDE.md 是文档级约束，靠 AI 自觉。生产项目用 ArchUnit 把规则变成 CI 护栏——违反就构建失败，不靠 AI 自觉。

我的项目没 ArchUnit，但有替代机制——TDD 测试本身就是护栏。比如"per-UUID 锁串行化 append"这个规则，靠 `TestConcurrentAppend_100` 强制校验，违反就测试失败。

**3. 路径白名单保护存量代码**：insurance_mall 的 §0 规则最巧妙——AI 改存量代码时保持现有风格，新建代码才按新规范。这避免 AI 把历史代码"顺手重构"污染风格。

我的项目对齐：CLAUDE.md 里写"prefer editing existing files to creating new ones"，AI 协作时确实遵守——比如加 NotifyHook 时改 types.go 而不是新建 notify.go。

**追问"和直接写 prompt 区别"**：prompt 是临时指令，CLAUDE.md 是持久契约。临时指令容易忘，持久契约会自动加载。生产项目进一步用 paths 机制让规则按需触发——这是 insurance_mall 的核心创新，避免 CLAUDE.md 膨胀到上下文爆炸。

---

### Q18：你的 AI 协作流程和生产项目（如 insurance_mall）的 DDD harness 有什么差距？

**为什么问**：验证你是否对齐过生产级 AI 编码规范，能否讲出真实差距。

**参考答案**（坦诚承认 gap）：

我的项目对齐了**哲学层**，但没对齐**工程化护栏层**。

**对齐的部分**（哲学层）：

1. Karpathy 4 准则——简洁优先 / 精准修改 / 目标驱动 / 编码前思考。我的 ponytail skill 完全对齐
2. 长任务三件套——EXECUTION_PLAN + QUESTIONS + FINAL_REPORT，对齐 insurance_mall 的 docs/YYYY-MM-DD-需求中文名/ 工作区
3. TDD 红→绿→重构——把"添加验证"转化为"为无效输入写测试"，对齐 Karpathy 目标驱动执行

**未对齐的部分**（工程化护栏层）：

1. **ArchUnit 可执行护栏**：insurance_mall 有 10 条 ArchUnit 规则 CI 自动校验（outapi 单方法 / UseCase 不互调 / domain 不依赖 Spring 等）。我的项目没有 CI 强制校验架构约束——靠 TDD 测试做替代，但不如 ArchUnit 严格
2. **paths frontmatter 按需加载**：insurance_mall 用 `.agent-harness/rules/*.md` 配 paths 触发，处理 `.java` 自动加载 java-coding-standards。我的项目 CLAUDE.md 是静态规则，没有按文件类型触发
3. **窄端口/适配器分离**：insurance_mall 有 OutApi 接口（每接口一方法）+ OutAdaptor 实现的 DDD 分层。我的项目是 client 包内文件级拆分，没有端口/适配器分离
4. **新旧规范过渡判断**：insurance_mall §0 规则——改存量保持现有风格，新建按新规范。我的项目没显式规则，但实际遵循了"prefer editing existing files"

**为什么没对齐**：项目定位不同。insurance_mall 是生产 DDD 项目，需要工程化护栏防止 AI 污染架构。我的项目是课程作业+工程化改造，scope 不需要 ArchUnit。但哲学对齐已经足够讲故事——面试官追问时能讲清"对齐了什么、没对齐什么、为什么"，比硬撑"全对齐"可信。

---

### Q19：insurance_mall 的 §0 新旧规范过渡判断为什么重要？AI 协作时怎么避免污染存量代码？

**为什么问**：考察对生产级 AI 编码规范的理解深度——这是 insurance_mall 的核心创新之一。

**参考答案**：

§0 规则解决的是**AI 协作最大的隐患**：AI 倾向于"顺手重构"——改一个方法时把周边代码也"优化"成新风格，导致存量代码风格污染。

insurance_mall 的 3 条判断规则：
- ① 创建新文件 → 严格遵循新规范
- ② 重构现有文件结构 → 向新规范靠拢，但不改业务逻辑
- ③ 修改存量业务逻辑 → 保持现有风格，最小化修改

**为什么重要**：生产项目代码库大，新旧规范过渡期长。如果 AI 每次改存量代码都"顺手重构"，会导致：
1. PR diff 膨胀——review 困难
2. 风格不一致——同一文件新旧风格混用
3. 回归风险——重构可能引入 bug

**AI 协作时怎么避免**：
1. CLAUDE.md / AGENTS.md 显式写规则——"只修改任务要求的部分，不重构周边无关代码"
2. paths 白名单——限定 AI 可改的路径
3. PR review 检查 diff 范围——每行修改都能追溯到用户请求

**我的项目对齐情况**：
- CLAUDE.md 写了"prefer editing existing files to creating new ones"
- 实际协作时确实遵守——比如加 NotifyHook 时改 types.go 而不是新建 notify.go
- 但没显式 §0 规则，靠 AI 自觉 + 我 review

**生产级改进**：如果要做生产级 harness，会把 §0 规则写进 CLAUDE.md，配 paths 白名单（限定可改路径），再加 ArchUnit 校验风格一致性。

---

### Q20：你提到 ponytail 简洁优先原则，和 Karpathy 的准则什么关系？具体怎么落地？

**为什么问**：验证你是否真理解简洁优先的工程含义，而不是口号。

**参考答案**：

ponytail 是我项目用的 skill，完全对齐 Karpathy 4 准则中的"简洁优先"。核心思想：**用最少代码解决问题，不为一次性代码创建抽象**。

**7 级 ladder**（ponytail 的具体落地）：
1. 这个功能需要存在吗？（YAGNI）
2. 已在代码库里有 helper 吗？（reuse）
3. stdlib 能做吗？
4. 原生平台特性覆盖吗？
5. 已安装依赖能解决吗？
6. 能写成一行吗？
7. 才写最小代码

**具体例子**（本次简历打磨中的落地）：

加 NotifyHook 时，第一反应是建 notify.go 新文件 + Notify struct + Notify interface。但按 ponytail ladder：
- 第 1 级：需要 Notify struct 吗？不需要——只是函数变量
- 第 2 级：stdlib 有吗？没有，但 Go 函数变量本身就够了
- 第 6 级：能一行吗？能——`var NotifyHook func(recipient, event, payload string)`

最终实现就 1 行变量 + 1 个 Notify 包装函数。没建 interface，没建 struct，没建 notify.go 新文件——改 types.go 加 10 行代码搞定。

**对比"不用 ponytail"的版本**：
- 建 `NotifyService` interface
- 建 `InMemoryNotifyService` 实现
- 建 `notify.go` 文件
- 加 `NotifyServiceFactory`
- ~80 行代码

**学到的**：AI 协作最大的诱惑是"过度抽象"——AI 倾向于建 interface/factory/config，因为训练数据里这些模式常见。ponytail 强制走 ladder，每级问"真的需要吗"，把抽象压到最低。

**和 Karpathy 准则的对应**：
- "用最少代码解决" → ladder 第 7 级
- "不为一次性代码创建抽象" → ladder 第 1-2 级
- "资深工程师会觉得过于复杂吗" → ladder 每级的检验标准

---

### Q21：长任务三件套（EXECUTION_PLAN + QUESTIONS + FINAL_REPORT）为什么必要？AI 协作没有这套流程会怎样？

**为什么问**：验证你是否真懂三件套的价值，还是形式主义。

**参考答案**：

三件套解决的是**AI 协作最大的坑：上下文丢失**。

AI 协作跨多轮对话，每轮上下文窗口有限。没有三件套时：
- 第 1 轮决策"用 per-UUID 锁"
- 第 5 轮 AI 忘了，又提出"用全局锁"
- 第 10 轮 AI 又忘了，提出"用 channel 同步"
- 反复返工，效率低

有三件套时：
- EXECUTION_PLAN 记录 9 个 task 状态（PENDING/DONE/WAITING_CONFIRMATION）
- QUESTIONS 记录 5 个决策问题（Q-001 到 Q-005）+ 状态机（OPEN/RESOLVED）
- 每轮 AI 从文件读状态，不靠聊天上下文恢复

**具体例子**（本次简历打磨）：

Q-004 我问用户"Directory 权限继承是否必要"，用户决定"必做"。这个决策记在 QUESTIONS.md 里，跨多轮对话后 AI 仍然知道"B05 必须做"——不会忘。

如果不落文件，第 5 轮 AI 可能会说"Directory 权限继承看起来过度设计，建议跳过"——忘了几轮前的决策。

**三件套 vs GitHub Issue**：
- Issue 适合多任务跟踪（每个 issue 独立）
- 三件套是**单任务的三视角**：计划（EXECUTION_PLAN）+ 决策（QUESTIONS）+ 报告（FINAL_REPORT）
- 三件套在同一目录，互相引用，形成完整任务档案

**生产项目对齐**：insurance_mall 的 CLAUDE.md 明确要求"每个需求在仓库根目录 `docs/YYYY-MM-DD-需求中文名/` 唯一工作区"——和我用的 `docs/2026-08-17-resume-polish/` 完全同款设计。这不是巧合，是 AI 编码规范工程化的通用模式。

---

### Q22：如果让你给团队设计 AI 编码规范 harness，你会怎么做？

**为什么问**：考察从消费者到设计者的跃迁——能否把学到的设计思想应用到新场景。

**参考答案**（分层设计）：

我会分 4 层设计，对应 insurance_mall 的层次：

**第 1 层：哲学层（CLAUDE.md / AGENTS.md）**

写 Karpathy 4 准则 + 项目特定的 AI 行为约束。这层是文档级，靠 AI 自觉。
- 编码前思考 / 简洁优先 / 精准修改 / 目标驱动
- 业务线识别规则（如 insurance_mall 的药划算/C端/B端识别）
- 路径白名单（哪些路径可改，哪些不能动）

**第 2 层：规则层（.agent-harness/rules/）**

按 paths frontmatter 按需加载。这层是上下文级，处理特定文件类型时触发。
- `java-coding-standards.md` paths: `**/src/main/**/*.java`
- `testing-standards.md` paths: `**/src/test/**`
- `logging-standards.md` paths: `**/src/main/**/*.java`

**关键设计**：paths 触发避免上下文膨胀——处理 Java 文件时不加载测试规范，反之亦然。

**第 3 层：护栏层（ArchUnit / CI）**

可执行规则，CI 强制校验。这层是硬约束，不靠 AI 自觉。
- outapi 单方法
- UseCase 不互调
- domain 不依赖 Spring
- entity 禁 public setter

**关键设计**：护栏层让规则从"应该做"变成"必须做"。AI 违反规则时 CI 失败，不是等 review 发现。

**第 4 层（可选）：过程层（docs/YYYY-MM-DD-需求中文名/）**

长任务三件套工作区。这层是任务级，跨轮恢复上下文。
- EXECUTION_PLAN + QUESTIONS + FINAL_REPORT
- 跨天续做不改名

**给团队推广时的关键点**：
1. 不要一次性铺所有层——先哲学层 + 过程层，跑顺后再加规则层和护栏层
2. 护栏层必须 CI 强制——文档级规则容易被 AI 忽略
3. paths 机制是核心创新——避免上下文膨胀，比"把所有规则塞 CLAUDE.md"高效
4. 新旧规范过渡判断（§0）必须显式写——避免 AI 顺手重构污染存量代码

**我的项目对齐情况**：哲学层 ✅ + 过程层 ✅ + 规则层 ❌（没 paths 机制）+ 护栏层 ❌（没 ArchUnit）。如果做生产级 harness，会补规则层和护栏层。

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
| P0 | Q17-Q22 AI 协作工程化（深度对齐 insurance_mall 设计） |
| P1 | Q9-Q12 八股（密码学基础） |
| P1 | Q7-Q8 系统设计扩展 |
| P2 | Q14-Q16 行为面（反思类 + AI 协作流程） |

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
