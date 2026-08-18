# insurance_mall submitOrder 链路深挖 - 面试 QA

> 文档日期：2026-08-18
> 研究对象：`insurance-mall-order/.../CustomerSubmitOrderService.submitOrder`
> 支撑材料：`/Users/gaoruihuan/IdeaProjects/insurance_mall/docs/2026-08-18-商保商城submitOrder链路深挖/submitOrder链路深挖.md`
> 适用场景：后端/服务端岗位面试，针对金融场景提单链路的深度追问

## 使用说明

本文档基于 submitOrder 链路深挖文档（1200 行，8 个子点）整理 10 个面试 QA。

每个 QA 包含：
- **为什么问**：面试官视角的考察意图
- **参考答案**：3 分钟口述版 + 关键代码引用
- **追问预期**：可能被深挖的延伸问题

答题节奏：首次回答 30 秒口述版，被追问展开 3 分钟版。

---

## Q1：你提到 submitOrder 用了主库强制读取（ZebraForceMasterHelper），为什么不直接走 `@Transactional`？为什么打标放在 Facade 入口而不是 UseCase 内部？

**为什么问**：考察对主从延迟 + ThreadLocal 传播的深度理解。区分"知道用法"和"懂底层机制"。

**参考答案**：

**为什么不用 `@Transactional`**：`@Transactional` 控制的是事务边界，不是读写分离。提单场景的关键问题是——查到未支付单之后立刻要决定是否创建新单，主从延迟可能导致从库还没同步到刚提交的数据，查不到未支付单 → 重复创建。`@Transactional` 默认走从库（查询不进事务），解决不了主从延迟。

**为什么打标放 Facade 入口**：`ZebraForceMasterHelper` 用的是 ThreadLocal，作用范围是当前线程的整个调用链。Facade 入口打标一次，UseCase 内所有 Repository 查询都走主库。如果在每个 Repository 内打标，会有 3 个问题：
1. 重复打标，代码冗余
2. 容易漏——新加 Repository 忘记打标就走从库
3. finally 清理也分散，泄漏风险大

**关键约束**：ThreadLocal 跨线程不传递。如果 UseCase 内部引入 `CompletableFuture` 异步查询，主库标会失效——异步查询走从库。这是隐式约束，代码里没显式标注。所以 `DistributedLockImpl.lockAndCall` 必须是同步调用（同线程执行 Callable），一旦改成线程池异步，主库强制就失效。

**追问"为什么不封装"**：项目里有 `DbUtil.forceMaster(Callable)` 封装了 try-finally 自动清理。但 Facade 入口用了手动 try-finally，原因是 facade 的 try 块还包了异常转换 + Cat 埋点，无法用单一 Callable 表达。这是工程实际的折中。

**支撑代码**：
- `SubmitOrderServiceImpl.java:101` — `ZebraForceMasterHelper.forceMasterInLocalContext()`
- `SubmitOrderServiceImpl.java:147` — `finally { ZebraForceMasterHelper.clearLocalContext(); }`
- `DbUtil.java:34-46` — forceMaster(Callable) 封装

---

## Q2：分布式锁用了双重维度（commodityId + categoryCode），为什么不只用一个维度？多把锁怎么避免死锁？

**为什么问**：考察锁粒度设计 + MultiLock 实现机制。

**参考答案**：

**为什么双维度**：
- commodityId 维度：防同款商品并发提单（用户开两个 tab 同时买同款）
- categoryCode 维度：防跨商品但同险种重复投保（百万医疗有 SPU A 和 SPU B，都属于"百万医疗"类目，不能同时买两份）

只 commodityId 防不住跨 SPU 的重复；只 categoryCode 防不住同 SPU 的并发。两者必须都锁。

**MultiLock 怎么避免死锁**：`distributedLockManager.getNewMultiLock(keys, expiredTime)` 返回组合锁，内部对多个 key **按 hash 排序后依次 acquire**。排序保证所有线程按相同顺序获取锁，避免经典的"线程 A 先拿 lock1 再拿 lock2，线程 B 先拿 lock2 再拿 lock1"死锁。

**锁底层**：Cerberus 分布式锁服务 + Squirrel（Redis 集群）+ WatchDog 后台线程自动续租。

**超时 30 秒的权衡**：业务处理 ~3 秒，30 秒是 10x 余量。WatchDog 会在锁快过期时自动续租，所以实际持有可以超过 30 秒。30 秒是故障兜底——进程崩溃时 WatchDog 也死，30 秒后锁自动释放，避免死锁。

**追问"N 个被保人 = 2N 把锁性能"**：团险场景几十个被保人会产生几十把锁，MultiLock 串行 acquire 时间长。优化路径：
1. 把 commodityId 维度合并成一把（同 commodityId 的 N 个被保人合并）
2. 用 tryLock 非阻塞获取，获取失败立即降级

**锁 key 隐私设计**：用 SHA256 而不是明文身份证。身份证号不进 Redis key，只进 SHA256 摘要。日志、Redis 监控、Squirrel 后台都看不到明文身份证——符合 `logging-standards.md` 脱敏要求。

**支撑代码**：
- `SubmitOrderServiceImpl.java:326-349` — getDistributeLocks 双维度 key
- `DistributedLockImpl.java:100-122` — lockAndCall MultiLock 实现

---

## Q3：重复投保校验为什么 fail-close（异常时默认拦截）？这会不会导致误杀？

**为什么问**：考察异常处理的设计哲学——金融场景的合规 vs 体验权衡。

**参考答案**：

**为什么 fail-close**：重复投保是金融合规问题——如果漏判，用户重复承保，理赔时会有纠纷。误杀只是用户体验差（无法提单，重试一次就好），漏判是合规事故。两者风险等级不同，宁可误杀不漏判。

具体代码（`CustomerSubmitOrderService.java:424-428`）：
```java
try {
    InstallmentSummaryDto summary = mallInstallmentGateway
        .queryInstallmentRecordSimpleInfoForMedicine(...);
    return !CommonConstants.SUMMARY_TERMINATE_STATUS_SET.contains(summary.getSummaryStatusCode());
} catch (Exception e) {
    log.error("无法确认分期单是否有效详单,不能再重复投保");
    return true;   // ★ fail-close
}
```

**会不会误杀**：会，但场景有限：
1. 分期服务 RPC 超时 / 网络抖动 → 用户重试一次就能成功
2. 分期服务宕机 → 大面积误杀，但这种情况本来就应该 fail-close，不应该让用户继续提单（因为无法校验是否重复）

**追问"为什么不用 fail-open + 人工补偿"**：金融场景下人工补偿成本极高——重复承保后要主动联系用户退保、退款，还可能涉及监管报告。fail-close 是用"用户体验换合规安全"，符合金融业务特性。

**追问"如何降低误杀率"**：
1. RPC 加重试（当前代码没看到重试）
2. 分期服务降级时走缓存（但缓存可能过期）
3. 加监控告警，fail-close 触发时立即报警

**追问"趸缴 vs 期缴为什么区分处理"**：
- 趸缴（一次性付款）：DB 状态"已支付"就一定有效，不调 RPC
- 期缴（分期付款）：DB 状态"已支付"但分期 summary 可能已被终止，必须 RPC 确认

这是充血方法 `isSinglePayment` / `isRegularPayment` 的设计——状态判断内聚在领域实体。

**支撑代码**：
- `CustomerSubmitOrderService.java:386-437` — hasBuyCustomerInsurance
- `CustomerSubmitOrderService.java:424-428` — fail-close 关键代码

---

## Q4：事务为什么用编程式（transactionTemplate.execute）而不是 `@Transactional` 注解？

**为什么问**：考察事务边界的精准控制能力。

**参考答案**：

4 个原因：

**1. 事务边界精准**：只包 4 个写操作（save timeout / save order / save items / createTimeoutRecord），不包前面的查询和后面的 MQ/事件。`@Transactional` 注解会包整个方法，把查询也包进事务，事务时间变长，数据库连接占用久。

**2. 异常控制灵活**：注解方式默认 `RuntimeException` 触发回滚，但提单场景需要 catch + 包装成 `BizRuntimeException` 再 rethrow。编程式可以精确控制：
```java
} catch (Exception e) {
    throw new BizRuntimeException(e);   // rethrow 触发回滚
}
```

**3. 返回值需要**：编程式事务可以返回任意值。这里返回 null，但其他场景可以返回实体 ID 等。

**4. 嵌套事务控制**：`transactionTemplate.execute` 默认 `PROPAGATION_REQUIRED`，可以灵活配置传播级别。Repository 自带 `@Transactional(REQUIRED)`，会加入外层编程式事务。

**追问"Repository 自带 `@Transactional(REQUIRED)` 会不会重复开事务"**：不会。`PROPAGATION_REQUIRED` 的语义是"如果当前有事务就加入，没有才新建"。Repository 调用时外层编程式事务已存在，Repository 直接加入，不会重复开。

**追问"事务范围是不是太大"**：是潜在风险。4 个写操作 + 加密 + 唯一索引写入，单事务可能较长。批量保存是 forEach + save（不是真正 batch insert），团险 N 个被保人性能差。优化路径：真正的 batch insert + 把加密放到事务外预计算。

**4 个写操作的顺序设计**：
1. timeout（超时单，独立）
2. order（主订单）
3. items（详单，依赖 orderId）
4. pushRecord（推送订单中心延迟任务，依赖 orderId）

顺序按外键依赖：主订单先于详单，详单先于依赖 orderId 的延迟任务。超时单先写——即使后续失败，超时单会触发回滚，但超时单本身不影响主流程。

**支撑代码**：
- `CustomerSubmitOrderService.java:198-213` — 编程式事务
- `CommercialMallOrderRepositoryImpl.java:51-83` — Repository 自带 @Transactional(REQUIRED) + 加密
- `CommercialMallOrderItemRepositoryImpl.java:1931-1942` — 批量保存 forEach + save

---

## Q5：事务后置事件为什么用"事件 + 延迟任务表"双保险？只用 MQ 不行吗？

**为什么问**：考察最终一致性方案的选型能力。

**参考答案**：

**为什么双保险**：金融场景下推送订单中心失败不能丢，必须有兜底。

**只用 MQ 的问题**：
1. MQ 可能丢消息（broker 故障、消费者宕机）
2. MQ 消费失败后重试次数有限，超过就进死信队列，需要人工处理
3. MQ 不保证顺序，订单中心可能先收到"取消"再收到"创建"

**双保险的设计**：
1. **事务内**：把 EventVO 序列化为 JSON 写入延迟任务表（`mall_order_policy_timeout`），3 秒后到期
2. **事务外**：发 Spring Event，`@Async` 异步推送订单中心
3. **推送成功**：删除延迟任务
4. **推送失败**：延迟任务到期后由 Job 扫表重试

**关键设计**：延迟任务表存的是 EventVO 的 JSON，不是 orderId。Job 重试时反序列化 EventVO 重新推送，保证字段完整。

**为什么用 Spring Event 而不是直接调订单中心**：
1. 解耦——UseCase 不依赖订单中心接口
2. 异步——`@Async` 不阻塞主流程
3. 可替换——以后改 MQ 推送只改 listener

**追问"3 秒延迟为什么"**：3 秒是经验值——异步推送一般 1 秒内完成，3 秒后还没删除说明推送失败，Job 重试。比 MQ 重试间隔短，用户体验好。

**追问"为什么不用 `@TransactionalEventListener(AFTER_COMMIT)`"**：Spring 4.2+ 提供的 `@TransactionalEventListener(phase = AFTER_COMMIT)` 可以在事务提交后才触发，比手动事务外发更优雅。当前代码用 `@EventListener + @Async` 也能工作，但语义上 `@TransactionalEventListener` 更清晰——避免事件在事务回滚时还触发。这是潜在的优化点。

**追问"延迟任务表会不会膨胀"**：会。如果推送成功率低，延迟任务会堆积。需要定期清理 + 加监控告警。

**完整事件流程**：
```
事务内:
  save order / items / timeout
  createTimeoutRecord(EventVO 序列化为 JSON, 3 秒后到期)
  ↓ 事务提交

事务外:
  publishPushOrderEvent(PushOrderEvent)
  ↓ Spring ApplicationEventPublisher
  ↓
PushOrderEventListener (@Async)
  ├─ commercialOrderCenterDelegate.pushOrder(eventVO)   推送订单中心
  ├─ Cat.logEvent(...)                                   监控埋点
  └─ commercialOrderTimeOutService.removeTimeoutRecord  删除延迟任务

失败兜底:
  Job 扫 mall_order_policy_timeout 表
  ↓ 到期记录
  ↓ 反序列化 EventVO JSON
  ↓ 重新推送订单中心
```

**支撑代码**：
- `CustomerSubmitOrderService.java:214-234` — otherProcess + publishPushOrderCenterEvent
- `CustomerSubmitOrderService.java:204-207` — 事务内 createTimeoutRecord
- `event/listener/PushOrderEventListener.java` — @Async @EventListener

---

## Q6：被保人索引用 MD5 + FNV hash 双字段，为什么不直接用身份证号建索引？

**为什么问**：考察隐私设计 + 索引性能权衡。

**参考答案**：

**为什么不直接用身份证号**：
1. **隐私风险**：身份证号进索引、日志、监控都会暴露。DBA 查索引、Squirrel 后台看锁 key 都能看到明文身份证
2. **合规要求**：`logging-standards.md` 要求敏感信息脱敏，身份证号是高敏

**为什么用 MD5**：
1. 不可逆——DB 脱裤拿不到明文
2. 固定 32 字节——索引大小可控
3. 性能好——MD5 计算快

**为什么加 FNV hash 双字段**：
- `unique_hash_num`（FNV hash，Long 类型）：用于分桶/范围查询，数字类型索引比字符串快
- `unique_hash`（MD5，String）：精确匹配

双字段索引设计：先 hash 分桶缩小扫描范围，再 MD5 精确匹配，避免长字符串索引的性能开销。这是美团内部表结构的常见模式。

**潜在风险**：
1. **MD5 无盐**：身份证号格式固定（18 位，前 6 位地区码 + 8 位生日 + 3 位顺序 + 1 位校验），枚举空间小，理论上可被彩虹表反解。要更安全应该改 SHA256 + 应用层盐
2. **MD5 碰撞**：理论上存在，但身份证号 + 证件类型组合空间有限，实际碰撞概率可忽略

**追问"为什么不直接加密存储"**：加密存储适合"需要还原明文"的场景（如手机号显示）。被保人索引用于查询匹配，不需要还原，hash 更合适——查询时也 hash 一下比对即可。

**追问"N 次查询性能"**：代码用 stream + map，每个 uniqueCode 单独查一次 DB。如果一次提单有 10 个被保人，会产生 10 次查询。注释里写了"后续可根据数量进行多线程并行查询"，但当前是串行。优化路径：改 IN 查询或并行。

**支撑代码**：
- `CustomerSubmitOrderService.java:157-162` — MD5 key 生成
- `CustomizedQueryRepository.java:420-437` — findOrderAndItemIdsBySubjectUniqueCodes 双字段查询
- `CommercialMallOrderItemRepositoryImpl.java:198-200` — 索引数据写入时机

---

## Q7：getUnpaidOrder 为什么是 size == 1 而不是 size >= 1？

**为什么问**：考察边界条件设计的严谨性。

**参考答案**：

**为什么 size == 1**：
- 正常场景：分布式锁 + 重复投保校验保证一个用户对一个商品最多一个未支付单
- size == 0：确实没有未支付单，继续走新建流程
- size == 1：复用这个未支付单
- size > 1：**异常状态**（数据不一致），不应该随便返回其中一个

**size > 1 是什么场景**：
1. 分布式锁失效（锁服务故障）
2. 老订单没走新流程索引，多次提单产生多个未支付单
3. 数据迁移不完整

**为什么 size > 1 不返回**：
1. 返回哪个都不对——可能返回已过期的，用户支付后订单中心状态不对
2. 应该告警——但当前代码静默走新建流程，是潜在风险

**追问"size > 1 应该怎么处理"**：
1. 加 Cat 告警，立即触发排查
2. 取最近创建的一个（最大 orderId）返回，加日志标注异常
3. 或者直接抛异常，让用户重试

**追问"为什么有新老双流程"**：老订单没有 `subject_unique_code` 索引，新流程查不到。新老并存是历史包袱——等老数据迁移完成后下线老逻辑。

**续保单排除设计**：`getDirectInsureOrder` 排除续保单/预约单/主动续保单——续保单不支持主动支付，所以从"未支付单"里排除。这是业务规则决定的，不是技术决策。

**支撑代码**：
- `CustomerSubmitOrderService.java:695-718` — getUnpaidOrder
- `CustomerSubmitOrderService.java:413-415` — size == 1 判断
- `CustomizedQueryRepository.java:2177` — getDirectInsureOrder 排除续保单

---

## Q8：锁内调用了 3 个 RPC（商品校验、分期查询），违反了"锁内禁止 RPC"规范，你怎么看？

**为什么问**：考察规范与实际的冲突处理能力——这是最强钩子，体现你理解 trade-off 而不是死记规范。

**参考答案**：

**规范与实际的冲突**：`java-coding-standards §7` 明确"锁内禁止 RPC 调用"。但提单场景下，商品校验和分期校验必须在锁内做——锁外校验完到锁内之间状态会变化（用户在其他 tab 买了同款），导致锁失效。

**实际的折中**：
1. RPC 调用尽量靠前（锁内靠后），先把无依赖的 RPC 做完
2. 锁超时设 30 秒，留足容错时间
3. Cerberus WatchDog 自动续租，避免 RPC 慢导致锁过期

**这是真正的设计权衡**：
- 严格遵守规范（锁内禁止 RPC）→ 业务正确性破坏（重复投保漏判）
- 违反规范（锁内 RPC）→ 性能风险（RPC 慢导致锁持有久）

金融场景下业务正确性 > 性能，所以选择违反规范。但应该：
1. RPC 加超时配置（避免无限等待）
2. RPC 加重试（降低单次失败概率）
3. 监控锁持有时间，超阈值告警

**追问"如何彻底解决"**：
1. 把 RPC 结果缓存到本地（短 TTL），锁内查缓存
2. 把校验前置到锁外，锁内只做幂等性检查（用版本号/序列号）
3. 用乐观锁代替分布式锁（CAS + retry），避免锁持有

**这是工程实际的常见情况**：规范是理想，实际有 trade-off。关键是**显式记录违反规范的原因和风险**，不是默默违反。当前代码注释里没说明为什么锁内 RPC，是文档缺失。

**3 个 RPC 调用清单**：
- `customerCommodityGateway.checkCommodity` — 调 insurance-mall-commodity 仓库
- `mallInstallmentGateway.queryInstallmentRecordSimpleInfoForMedicine` — 调分期服务
- `mallInstallmentGateway.batchQueryInstallmentRecordSimpleInfo` — 调分期服务（批量）

**支撑代码**：
- `CustomerSubmitOrderService.java:149` — checkCommodity RPC
- `CustomerSubmitOrderService.java:419-421` — queryInstallmentRecordSimpleInfoForMedicine RPC
- `CustomerSubmitOrderService.java:476-479` — batchQueryInstallmentRecordSimpleInfo RPC

---

## Q9：实体工厂用了静态方法 + 实例方法混合，为什么？这种风格一致性问题怎么解决？

**为什么问**：考察代码风格一致性 + 历史包袱处理。

**参考答案**：

**为什么混合**：历史原因。老 `CommercialMallOrderFactory`（无 customer 子包）全是静态方法；新 `customer/CommercialMallOrderFactory` 想用实例方法（注入 configGateway），但 `buildMallOrder` 还是静态的——因为静态方法无法用注入字段，所以 `configGateway` 字段成了死代码。

**潜在风险**：
1. 风格不一致——新代码混用静态/实例，调用方不知道该用哪种
2. 死代码——`configGateway` 注入了但没用，迷惑后来者
3. 新老工厂并存——容易调错，调到老工厂就走老流程

**怎么解决**：
1. **短期**：在 `buildMallOrder` 上加注释说明"静态方法不用 configGateway，实例方法才用"
2. **中期**：把 `buildMallOrder` 改成实例方法，统一风格
3. **长期**：老数据迁移完成后，下线老 `CommercialMallOrderFactory`

**追问"为什么不全改实例方法"**：静态方法调用方便（不用注入），历史代码大量用静态调用。改成实例方法需要改所有调用点，scope 大。渐进迁移是工程实际的折中。

**对照规范**：`ai-coding-guide §1.6` 要求命名后缀与包路径双向绑定，但没强制静态/实例风格。这是规范没覆盖的灰色地带。

**追问"新老工厂怎么区分"**：
- 老：`domain/factory/CommercialMallOrderFactory.java`
- 新：`domain/factory/customer/CommercialMallOrderFactory.java`（多了 `customer/` 子包）

调用方按 import 路径区分，容易调错。应该加 ArchUnit 规则禁止老工厂被新代码引用。

**支撑代码**：
- `domain/factory/customer/CommercialMallOrderFactory.java:86-148` — 新工厂（静态 + 实例混合）
- `domain/factory/CommercialMallOrderFactory.java` — 老工厂（全静态）
- `CustomerSubmitOrderService.java:182-186` — 静态 buildMallOrder + 实例 buildMallOrderItems 混用

---

## Q10：如果让你重构这个 submitOrder 方法，你会优先改什么？

**为什么问**：考察从消费者到设计者的跃迁 + 改造优先级判断。

**参考答案**：

按 ROI 排序：

**P0（必改）**：
1. **锁内 RPC 风险**：加 RPC 超时 + 重试 + 锁持有时间监控。不改架构，加防护
2. **`@TransactionalEventListener` 替换手动事务外发**：语义更清晰，避免事件在事务回滚时还触发
3. **size > 1 加告警**：数据不一致场景不能静默

**P1（应该改）**：
1. **批量保存改真 batch insert**：当前 forEach + save，团险性能差。改成 `mallOrderItemMapper.batchInsert`，加密预计算
2. **`getOldUnpaidOrderId` 改批量查询**：当前逐个被保人查 N 次 DB，改 IN 查询
3. **`hasBuyCustomerInsurance` 单查分期改批量**：和 `checkHasBuyDuplicateOrderTypes` 统一用 `batchQueryInstallmentRecordSimpleInfo`

**P2（可以改）**：
1. **新老工厂合并**：老数据迁移完成后下线老 `CommercialMallOrderFactory`
2. **MD5 改 SHA256 + 盐**：防彩虹表（虽然内部系统风险低）
3. **`INSURANCE_RETURN_FAIL` 状态重新评估**：退保失败状态是否应该算"有效"拦截重复投保

**不改的**：
- 双维度分布式锁——设计正确
- fail-close 原则——金融场景必须
- 主库强制——主从延迟问题真实存在
- 编程式事务——边界精准比注解好

**追问"为什么不直接重构架构"**：这是生产金融代码，重构风险高。渐进改造 + 充分测试 + 灰度发布是工程实际。一次性大重构容易引入 bug，且 review 困难。

**追问"重构怎么保证不破坏现有逻辑"**：
1. 先加测试覆盖现有行为（如果不全）
2. 重构小步进行，每步跑全量测试
3. 灰度发布——按 userId 分流，先 1% 流量验证
4. 加监控对比重构前后的关键指标（提单成功率、锁持有时间、RPC 调用次数）

**支撑代码**：
- 全文 `CustomerSubmitOrderService.java:147-216` — submitOrder 主体
- `CustomerSubmitOrderService.java:1931-1942` — 批量保存 forEach + save（P1 优化点）
- `CustomerSubmitOrderService.java:720-733` — getOldUnpaidOrderId 逐个查询（P1 优化点）

---

## 面试官视角的考察维度

| 维度 | 对应 QA | 优先级 |
|------|---------|--------|
| 主从延迟 + ThreadLocal | Q1 | P0 |
| 分布式锁 + 死锁防护 | Q2 | P0 |
| 异常处理哲学（fail-close） | Q3 | P0 |
| 事务边界控制 | Q4 | P0 |
| 最终一致性方案选型 | Q5 | P0 |
| 隐私 + 索引性能 | Q6 | P1 |
| 边界条件严谨性 | Q7 | P1 |
| 规范与实际的冲突 | Q8 | P0（最强钩子） |
| 代码风格一致性 | Q9 | P2 |
| 改造优先级判断 | Q10 | P0（行为面） |

## 准备建议

1. **重点准备 Q1/Q2/Q3/Q5/Q8/Q10**——这些是金融场景高频追问点
2. **Q8（锁内 RPC 违反规范）是最强钩子**——体现你理解规范与实际的 trade-off，不是死记规范
3. **Q10（重构优先级）是行为面素材**——体现你从消费者到设计者的跃迁
4. **每个 QA 都能指向代码具体行号**——这是深挖文档的价值，面试时能精确引用

## 答题节奏

| 场景 | 答案长度 |
|------|---------|
| 首次回答（不追问） | 30 秒口述版（参考答案第一段） |
| 面试官追问细节 | 3 分钟展开版（参考答案全文） |
| 涉及代码/数据 | 指向深挖文档 §子点 N + 代码行号 |

## 风险预警

| 风险 | 缓解 |
|------|------|
| 面试官问"你写过这种代码吗" | 诚实回答"研究过生产实现，自己项目里用过简化版" |
| 面试官深挖"为什么没用 MQ" | 诚实回答"项目 scope 不需要 MQ，但理解 MQ 的适用场景" |
| 面试官问"生产用户量" | 诚实回答"研究的是生产代码，自己项目是课程作业" |
| 面试官问"Cerberus/Squirrel 细节" | 诚实回答"了解原理，没在生产用过；可讲 Redis Redlock 对比" |

诚实 > 硬撑。承认"研究过生产实现"比假装"我写过"可信得多。

## 参考文档

- 深挖原文：`/Users/gaoruihuan/IdeaProjects/insurance_mall/docs/2026-08-18-商保商城submitOrder链路深挖/submitOrder链路深挖.md`
- insurance_mall AI coding 规范：`/Users/gaoruihuan/IdeaProjects/insurance_mall/.agent-harness/rules/`
- 项目面试 QA（22 个）：`docs/interview-qa.md`
- long-task 复盘：`docs/2026-08-18-long-task-retrospective.md`
