# CS161 工程化改造 - 问题清单

> 创建日期：2026-08-14
> 状态机：OPEN / ACTION_PENDING / RESOLVED / DEFERRED

## 一、已决策的问题

### Q-001 仓库改造策略

**状态**：RESOLVED
**问题**：是否在原 CS161 仓库 `aimee-RH/security-file-system` 的 main 分支直接改？
**用户决定**：B - 原仓库新建 `feature/engineering` 分支改，main 保留 CS161 课程提交结构
**处理结论**：已在本地创建 `feature/engineering` 分支。PR 将基于此分支创建，目标 main。
**关联批次**：所有

---

### Q-002 批次拆分粒度

**状态**：RESOLVED
**问题**：B01-B09 共 9 个批次是否合适？
**用户决定**：A - 9 个批次按当前计划执行（粒度细，进度可控）
**处理结论**：执行计划保持 B01-B09 9 个批次，按技术依赖顺序推进。
**关联批次**：所有

---

### Q-003 外部依赖引入

**状态**：RESOLVED
**问题**：B03/B04 引入 cobra + gin 外部依赖，是否接受？
**用户决定**：A - 接受 cobra + gin（社区标准，文档全）
**处理结论**：go.mod 将引入 `github.com/spf13/cobra` 和 `github.com/gin-gonic/gin`。
**关联批次**：B03, B04

---

### Q-004 Directory 权限继承是否必要

**状态**：RESOLVED
**问题**：B05 Directory 权限继承是否真的要做？
**用户决定**：A - 必做（apply 时讲"O(N) → O(1) 共享"是亮点）
**处理结论**：B05 按计划执行，新增 Directory 结构 + 5 级权限 + 继承机制。
**关联批次**：B05

---

### Q-005 MVP 范围

**状态**：RESOLVED
**问题**：MVP 范围如何定？
**用户决定**：B - 全量 = B01-B09（9 批次，1-2 周，完整 Agent 接入）
**处理结论**：执行全量 9 批次，不分阶段交付，目标最终 Draft PR。
**关联批次**：所有

---

## 二、上线 Checklist（待补充）

- [ ] 所有批次 DONE 或明确 WAITING_CONFIRMATION
- [ ] 黑盒测试 `client_test.go` 全通过
- [ ] 白盒单测覆盖关键路径
- [ ] README 更新工程化改造说明
- [ ] PR 描述含功能概述 + 未决事项
- [ ] Draft PR 创建成功

---

## 三、架构 TODO（后续扩展）

- **T-001**：加密搜索（知识发现域，B02 拆分后预留接口）
- **T-002**：跨设备实时协作（ProseMirror 类方案，超 MVP 范围）
- **T-003**：用户偏好记忆（学城 citadel-memory.md 类似机制）
- **T-004**：审批流程（学城 grant + audit 模式）
- **T-005**：安全屋模式（密级管理）

---

## 四、不明确点记录

无。
