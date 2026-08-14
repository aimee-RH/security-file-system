# CS161 工程化改造 - 执行计划

> 任务级状态：PLANNING
> 创建日期：2026-08-14
> 技术方案：/Users/gaoruihuan/docs/CS161工程化改造-技术方案-20260814.md
> 项目根：/Users/gaoruihuan/security-file-system

## 一、技术方案要点（精简版）

把 CS161 加密文件系统原型升级为工程化协作系统，借鉴学城 4 个核心设计，保留撤销前向保密差异化。

**4 个批次**：
1. **stepVersion 乐观锁** — 解决 `AppendToFile:785` 的 `Version++` 不阻塞问题
2. **业务域拆分** — 拆 client.go (1482 行) 成 6 个包
3. **CLI + REST API 接入层** — 让 AI Agent 可调用
4. **Directory 权限继承** — O(N) 共享成本降到 O(1)

**差异化保留**：RevokeAccess 已实现 BFS + 全密钥重生 + 新 UUID，**保留原逻辑**，只补审计 + 通知。

## 二、项目现状评估

| 文件 | 行数 | 角色 |
|------|------|------|
| `userlib.go` | 546 | 框架库（不可改） |
| `client/client.go` | 1482 | 主实现（待改造） |
| `client/client_unittest.go` | 60 | 白盒单元测试（可扩展） |
| `client_test/client_test.go` | 1210 | 黑盒集成测试（不可改） |
| `client_test/attacker_helpers.go` | 121 | 攻击者辅助（不可改） |

**测试框架**：Ginkgo v2 + Gomega（已在 import 中确认）
**构建命令**：无 go.mod，依赖外部 Go workspace（CS161 标准结构）
**内部依赖**：仅 Go 标准库（argon2/uuid/aes/rsa/hmac）+ Ginkgo/Gomega，**无内部库**

## 三、批次拆分与进度追踪表

| 批次 ID | 名称 | 优先级 | 状态 | 预计工作量 | 依赖批次 |
|---------|------|--------|------|-----------|---------|
| B01 | stepVersion 乐观锁 | P0 | DONE | 半天 | 无 |
| B02 | 业务域拆分 | P0 | DONE | 1 天 | B01 |
| B03 | CLI 命令包装 | P0 | PENDING | 半天 | B02 |
| B04 | REST API 服务 | P0 | PENDING | 1 天 | B03 |
| B05 | Directory + 权限继承 | P1 | PENDING | 1-2 天 | B02 |
| B06 | 鉴权层（用户+Agent 身份） | P1 | PENDING | 1 天 | B04 |
| B07 | 审计日志 | P1 | PENDING | 半天 | B04 |
| B08 | 频次限制 | P2 | PENDING | 半天 | B04 |
| B09 | 通知服务 | P2 | PENDING | 半天 | B04 |

**状态枚举**：PENDING / IN_PROGRESS / DONE / WAITING_CONFIRMATION / NOT_REQUIRED

## 四、批次接缝清单（测试边界先行）

### B01 stepVersion 乐观锁 ✅ DONE

**测试接缝**：
- 接缝 1：`SaveFileMetadataWithVersion` — 验证版本不匹配返回 `ErrStepVersionConflict`、版本匹配保存成功、连续递增不冲突
- 接缝 2：`AppendToFile` 内部使用乐观锁 + stale version 客户端保存冲突场景
- 接缝 3：`AppendWithRetry` — 无冲突时第一次成功 + maxRetry=0 也至少调一次

**已知限制**（记入代码注释）：
- CS161 限制不允许 `import "sync"`，无法用 mutex 实现真并发原子性
- 单线程下版本检测有效；多 goroutine 真并发下 Load+Check+Store 不原子（已知限制，B02 拆分时引入 userlib 外层包同步）
- CS161 限制不允许 `import "time"`，`AppendWithRetry` 无指数退避，纯循环重试

**不测**：
- 真实多 goroutine 并发冲突（接缝 2 用单线程模拟 stale version 替代）
- 真实网络延迟

**测试结果**：7 个 spec 全 PASS（接缝 1/2/3 全覆盖）；黑盒测试 38/39 通过（baseline 一致，无回归）

### B02 业务域拆分

**测试接缝**：
- 接缝 1：包级别 import 关系 — 验证 `governance` 不 import `discovery`（用 go vet 或 ast 检查）
- 接缝 2：原有功能不回归 — 跑 `client_test.go` 黑盒测试，所有用例通过

**不测**：拆分本身（纯重构，无行为变化）

### B03 CLI 命令包装

**测试接缝**：
- 接缝 1：CLI 入口 — 用 exec.Command 调用 `cs161 user init`，验证 stdout 含 token
- 接缝 2：命令路由 — Stub 底层 `InitUser`，验证 CLI 参数正确传递
- 接缝 3：错误返回 — 验证错误以非零 exit code + stderr 输出

**不测**：CLI 框架自身（cobra）

### B04 REST API 服务

**测试接缝**：
- 接缝 1：HTTP 路由 — `httptest.NewServer` 起 server，发请求验证响应
- 接缝 2：handler 调用底层 — Stub `User.StoreFile`，验证 handler 传递参数
- 接缝 3：错误处理 — 传非法 JSON，验证 400 响应

**不测**：gin 框架自身

### B05 Directory 权限继承

**测试接缝**：
- 接缝 1：`ResolvePermission` 递归 — Stub Directory 加载，验证继承链
- 接缝 2：移动后继承变更 — Stub 文件移动，验证新继承生效、显式权限保留
- 接缝 3：断开/恢复继承 — 验证 `inherit --action remove/restore` 行为

**不测**：底层 Datastore

### B06-B09 鉴权 / 审计 / 限流 / 通知

**测试接缝**：
- B06 鉴权：HTTP middleware，验证无 token 返回 401，有 token 通过
- B07 审计：Stub Datastore.Set，验证所有写操作调用 LogAudit
- B08 限流：连续调用 N+1 次，验证第 N+1 次返回 429
- B09 通知：Stub 通知 channel，验证撤销操作触发通知

## 五、执行顺序

按技术依赖（最小依赖先做）：

```
B01 (stepVersion) ─┐
                   ├─→ B02 (业务域拆分) ─┬─→ B03 (CLI) ─→ B04 (REST) ─→ B06/B07/B08/B09
                   │                      └─→ B05 (Directory)
                   └─→（独立）
```

**首推 B01**：最小依赖、最高 ROI（半天可完成，apply 时讲并发解决）。

## 六、关键约束

1. **不破坏黑盒测试**：`client_test.go` 1210 行不能改，所有改造后必须通过。
2. **userlib.go 不可改**：框架库，所有改动在 client/ 目录。
3. **撤销前向保密保留**：`RevokeAccess` 的 BFS + 全密钥重生 + 新 UUID 逻辑不动，只补审计调用。
4. **不明确点入 QUESTIONS.md**：不靠脑子记。

## 七、风险与限制

| 风险 | 说明 | 缓解 |
|------|------|------|
| 无 go.mod | CS161 标准结构，依赖外部 workspace | 本地建 go.mod 或在原 CS161 环境跑测试 |
| client.go 1482 行重构 | 拆分可能引入回归 | 每批次后跑黑盒测试 |
| CLI + REST 是新代码 | 增加项目复杂度 | P0 先做最小可演示，P1/P2 渐进 |
| 业务域拆分影响 CS161 提交结构 | 课程项目原结构不可破坏 | 拆分在 feature/engineering 分支做，main 保留原结构 |

## 八、用户决策点（需用户确认）

见 `QUESTIONS.md` 的 OPEN 项，汇总：

1. **Q-001**：是否在原 CS161 仓库直接改，还是 fork 后改？
2. **Q-002**：批次拆分粒度（B01-B09 9 个批次）是否合适？
3. **Q-003**：B03/B04 引入 cobra/gin 外部依赖，是否接受？
4. **Q-004**：B05 Directory 是否真的要做（课程项目可能过度设计）？
5. **Q-005**：MVP 范围——只做 B01+B02+B03+B05，还是全做 B01-B09？
