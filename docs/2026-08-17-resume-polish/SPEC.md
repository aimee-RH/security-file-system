# 简历打磨 - 并发基准 + 威胁模型 + README

> 创建日期：2026-08-17
> 项目根：/Users/gaoruihuan/security-file-system
> 目标岗位：后端/服务端开发
> 项目定位：简历辅助项目（2-3 行）
> 时间预算：3-5 天
> 开发方式：TDD（Red → Green → Refactor）

## 一、目标

把"加密文件系统"从课程作业升级为可写进简历的辅助项目。简历只有 2-3 行，每个 bullet 都要有面试官会追问的深度。

**最终简历样例**：

```
加密文件系统（Go · 不可信存储）
- per-UUID 锁+stepVersion 乐观锁+指数退避解决多设备并发写入，100 并发 p99 < Xms，0 chunk 丢失
- BFS 撤销+全密钥重生实现前向保密，6 类攻击防御有测试验证（vs Dropbox/学城明确差异化）
- Agent 接入层：REST + Bearer 鉴权 + 令牌桶限流 + 审计日志
```

每个 bullet 都有可演示/可量化的支撑材料。

## 二、范围

**In**：
- 故事 1：并发基准测试（量化数据 + `docs/benchmark.md`）
- 故事 2：威胁模型测试（TDD 验证每个安全声明 + `docs/threat-model.md`）
- 故事 3：README 重写 + 架构图 + demo 脚本

**Out**：
- T-001~T-009 所有架构 TODO（功能扩展不增加简历深度）
- 持久化 Datastore（in-memory 够用直到不够用）
- 真实部署 / Docker 化
- 录屏（人工，不在 spec 范围）

## 三、TDD 工作流

每个故事按三步：

1. **Red** — 先写失败测试。跑一遍确认测试基础设施能跑、测试确实失败（或不符合预期）。
2. **Green** — 最小实现让测试通过。不做额外重构。
3. **Refactor** — 清理代码 + 生成文档/图表。再跑测试确认仍 PASS。

测试用例一旦写完即为契约，不在实现阶段改测试。

## 四、故事 1：并发基准（2 天）

### 4.1 测试用例（Red）

新增 `client/concurrency_bench_test.go`，所有测试用 Ginkgo Describe 或标准 testing 都可，跟随现有 `stepversion_test.go` 的 Ginkgo 风格。

| 测试函数 | 验证点 | 通过条件 |
|---------|--------|---------|
| `TestConcurrentAppend_10` | 10 goroutine 各 append 1 byte | 文件最终长度 = init+10，0 chunk 丢失 |
| `TestConcurrentAppend_50` | 50 goroutine | 文件最终长度 = init+50 |
| `TestConcurrentAppend_100` | 100 goroutine | 文件最终长度 = init+100 |
| `TestConcurrentAppend_NoDeadlock` | 100 goroutine + 5s context timeout | 全部完成，无超时 |
| `TestConcurrentAppend_Fairness` | 100 goroutine 记录完成时间 | max_wait < 1s，无饥饿 |
| `BenchmarkAppendWithRetry_Single` | 单 goroutine append 吞吐 | ns/op + B/op + allocs/op |
| `BenchmarkAppendWithRetry_Concurrent_10` | 10 并发 | 同上 |
| `BenchmarkAppendWithRetry_Concurrent_100` | 100 并发 | 同上 |
| `TestConflictRateCurve` | 1/10/50/100 并发下 retry 次数统计 | 输出表格，retry 率 < 30% |

**关键签名约定**（避免实现时再决定）：

```go
// 并发 append 不丢 chunk
func TestConcurrentAppend_N(t *testing.T, n int) {
    // init user, store "init" file
    // spawn n goroutines, each AppendWithRetry("f", "x", 5)
    // wg.Wait()
    // load file, assert len == 4 + n
}

// 死锁检测
func TestConcurrentAppend_NoDeadlock(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    // 100 goroutines with ctx, fail if ctx.Err() == DeadlineExceeded
}

// 公平性
func TestConcurrentAppend_Fairness(t *testing.T) {
    // 记录每个 goroutine 的 done timestamp
    // max - min < 1s
}

// 冲突率
func TestConflictRateCurve(t *testing.T) {
    // hook AppendWithRetry 统计 retry 次数
    // 输出 [{n:1, retries:0}, {n:10, retries:X}, {n:50, retries:Y}, {n:100, retries:Z}]
}
```

### 4.2 实现（Green）

- 把现有 `TestStepVersionConcurrentAppend`（在 `cmd/cs161-server/infra_test.go`）迁移到 `client/concurrency_bench_test.go`，泛化成 `TestConcurrentAppend_N(n)`
- 加 50/100 并发用例
- 加 `context.WithTimeout` 死锁检测
- 加 fairness 时间记录（`time.Now()` 在每个 goroutine done 时）
- 加 `Benchmark*` 函数（标准 `testing.B`）
- 加 conflict rate 统计 hook：`client.AppendRetryHook = func(retryCount int) { ... }`（在 `AppendWithRetry` 里调用，新增到 `types.go`）

### 4.3 重构（Refactor）

- 跑 `go test -bench=. -benchmem -count=5 ./client/ > docs/benchmark_raw.txt`
- 写 `docs/benchmark.md`：
  - 吞吐曲线（ASCII 图或 markdown table）
  - 冲突率曲线
  - 与"无锁基线"对比（如能做到）
  - 已知限制（如 100 并发 p99 高，记录升级路径：分片锁）
- 不改实现代码，只补文档

### 4.4 验收

- [ ] 9 个测试/benchmark 全 PASS
- [ ] `docs/benchmark.md` 含可引用的数字
- [ ] 100 并发 0 chunk 丢失
- [ ] 100 并发 5s 内完成（无死锁）
- [ ] 简历 bullet 1 的 `Xms` 有真实数字填入

## 五、故事 2：威胁模型（1.5 天）

### 5.1 测试用例（Red）

新增 `client/threat_model_test.go`，白盒测试（需要访问内部状态如 `fileEncKey`）。

| 测试函数 | 威胁类别 | 验证点 | 通过条件 |
|---------|---------|--------|---------|
| `TestRevokedUserCannotLoadNewContent` | 撤销后访问 | Bob LoadFile 失败 | 返回 error |
| `TestRevokedUserOldKeysFailOnNewChunks` | 旧密钥重放 | 用旧 fileEncKey LoadFileChunk 新 chunk | HMAC mismatch 错误 |
| `TestReplayInvitation` | invitation 重放 | 撤销后旧 invID AcceptInvitation | 失败（invitation 不存在） |
| `TestChunkSwapAttack` | chunk swap | 交换两个 chunk UUID 后 LoadFile | HMAC 验证失败（UUID 在 HMAC 输入里） |
| `TestMetadataRollbackAttack` | metadata rollback | 用旧 metadata 解新 chunk | HMAC mismatch（revoke 后 metadata 重生成） |
| `TestConflatedChunkAttack` | chunk 跨文件混用 | 用 fileA 的密钥解 fileB 的 chunk | HMAC mismatch |

**关键签名约定**：

```go
// 撤销后 Bob 无法读新内容
func TestRevokedUserCannotLoadNewContent(t *testing.T) {
    // alice stores "secret", shares with bob, bob accepts
    // alice revokes bob
    // alice appends "new data"
    // bob.LoadFile("secret") → expect error
}

// 旧密钥无法解新 chunk（前向保密核心）
func TestRevokedUserOldKeysFailOnNewChunks(t *testing.T) {
    // alice stores, shares with bob, bob accepts
    // 记录 bob 拿到的 fileEncKey/fileHMACKey（从 FileView 或 metadata 提取）
    // alice revokes bob（触发全密钥重生）
    // alice appends new chunk
    // 用旧 fileEncKey LoadFileChunk(newChunkUUID) → expect HMAC mismatch
}
```

### 5.2 实现（Green）

- 大部分测试**应该直接 PASS**（现有实现已抵抗这些攻击，这是 TDD 验证声明的价值）
- 如果某测试**失败**：
  - 定位漏洞
  - 修复（最小改动）
  - 在 `docs/threat-model.md` 记录"发现并修复了 X 漏洞"（额外亮点）
- `TestReplayInvitation` 可能需要新增检查：revocation 路径已 `DatastoreDelete(invID)`，但要确认 `AcceptInvitation` 在 invID 不存在时返回错误

### 5.3 重构（Refactor）

- 写 `docs/threat-model.md`：
  - 威胁列表（6 类，含攻击者能力假设）
  - 每类对应防御机制（代码位置 + 测试引用）
  - 对比表：

| 特性 | 本实现 | Dropbox | 学城 |
|------|--------|---------|------|
| 撤销后前向保密 | ✅ | ❌ | ❌ |
| chunk swap 防御 | ✅（HMAC 含 UUID） | N/A | N/A |
| metadata rollback | ✅ | ❌ | ❌ |
| 服务端明文 | ❌（端到端加密） | ✅ | ✅ |
| invitation 重放 | ✅（撤销即删除） | N/A | N/A |

### 5.4 验收

- [ ] 6 个威胁模型测试全 PASS
- [ ] `docs/threat-model.md` 完整，含对比表
- [ ] 简历 bullet 2 的"6 类攻击防御"可指向具体测试

## 六、故事 3：README + Demo（0.5 天）

### 6.1 测试用例（Red）

新增 `scripts/demo_test.go`（或 `cmd/cs161-cli/demo_test.go`）：

| 测试函数 | 验证点 | 通过条件 |
|---------|--------|---------|
| `TestEndToEndDemo` | 完整流程作为 Go 测试 | init 2 users → store → share → accept → append → revoke → 通知验证 全 PASS |
| `TestDemoScript` | 跑 `./scripts/demo.sh` | 退出码 0 |

### 6.2 实现（Green）

**README.md 重写**（当前是空的，这是简历项目致命伤）：

```markdown
# 加密文件系统（CS161 工程化改造）

> 不可信存储上的端到端加密文件系统，支持文件分块、共享、撤销前向保密、Agent 接入层。

## 核心特性
- 并发安全：per-UUID 锁 + stepVersion 乐观锁 + 指数退避（[benchmark](docs/benchmark.md)）
- 前向保密：BFS 撤销 + 全密钥重生（[threat model](docs/threat-model.md)）
- Agent 接入：REST + Bearer 鉴权 + 令牌桶限流 + 审计日志

## 架构
[mermaid 图]

## Quick Start
```bash
go run ./cmd/cs161-server    # 起 REST API :8080
go run ./cmd/cs161-cli user init --username alice --password pwd
./scripts/demo.sh            # 端到端 demo
```
```

**scripts/demo.sh**：bash 脚本，调 CLI 跑完整 demo，输出每步状态。

**mermaid 架构图**：User → CLI/REST → client pkg → Datastore（不可信）。

### 6.3 重构（Refactor）

- 跑 `./scripts/demo.sh` 确认无报错
- README 链接到 `docs/benchmark.md` 和 `docs/threat-model.md`

### 6.4 验收

- [ ] README.md 非空，含架构图 + Quick Start + 特性 bullet
- [ ] `scripts/demo.sh` 可执行，退出码 0
- [ ] `TestEndToEndDemo` PASS

## 七、执行顺序与时间

```
故事 1（并发基准，2 天）──┐
                          ├──→ 故事 3（README + Demo，0.5 天）
故事 2（威胁模型，1.5 天）┘
```

故事 1 和 2 可并行（独立文件），故事 3 依赖 1+2 的产出（README 要引用 benchmark.md 和 threat-model.md）。

总预算：3.5 天，留 1.5 天 buffer 给"测试发现真 bug 需要修复"和"benchmark 数字不好看需要优化"。

## 八、整体验收 Checklist

- [ ] 故事 1：9 个并发测试 PASS + `docs/benchmark.md` 完整
- [ ] 故事 2：6 个威胁模型测试 PASS + `docs/threat-model.md` 含对比表
- [ ] 故事 3：README 重写 + demo.sh 可跑
- [ ] 黑盒测试 `client_test.go` 38/39 通过（baseline 一致，无回归）
- [ ] 简历 3 个 bullet 每个都有可指向的 docs/test 支撑

## 九、不做（YAGNI）

- T-001~T-009 架构 TODO
- 持久化 Datastore
- 真实部署 / Docker
- 录屏 / 截图（人工）
- 简历文案最终敲定（人工）
- 性能优化（除非 benchmark 数字差到无法引用）

## 十、风险

| 风险 | 说明 | 缓解 |
|------|------|------|
| benchmark 数字难看 | 100 并发 p99 可能很高 | 如差，作为已知限制记录；分片锁作为升级路径（ponytail 注释已留） |
| 威胁模型测试发现真 bug | 现有实现可能有漏洞 | 修复 + 记录，作为"发现并修复"的额外亮点 |
| 时间超预算 | 测试比预期多 | 砍故事 3 的 demo.sh，保留 README + 测试 |
| 简历 bullet 数字填不出来 | benchmark 跑不出有意义的 p99 | 改用吞吐数字（ops/sec）或冲突率 |
