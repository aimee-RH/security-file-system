package client

// 故事 1：并发基准测试（TDD Red → Green）
//
// 验证三个维度：
//   1. 正确性：N 并发 append 不丢 chunk
//   2. 活性：无死锁、无饥饿
//   3. 性能：吞吐 + 冲突率曲线
//
// 测试是契约——一旦写完不在实现阶段改测试。
// 如测试失败，修实现，不改测试。

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	userlib "github.com/cs161-staff/project2-userlib"
)

// helper：跑 N 个 goroutine 并发 append 单字节，返回最终文件长度 + 错误数
func runConcurrentAppend(t *testing.T, n int) (finalLen int, errCount int) {
	t.Helper()
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	alice, err := InitUser("alice", "pwd123")
	if err != nil {
		t.Fatalf("InitUser: %v", err)
	}
	if err := alice.StoreFile("concurrent.txt", []byte("init")); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	var wg sync.WaitGroup
	var errs atomic.Int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if err := alice.AppendWithRetry("concurrent.txt", []byte("x"), 5); err != nil {
				errs.Add(1)
			}
		}()
	}
	wg.Wait()

	data, err := alice.LoadFile("concurrent.txt")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return len(data), int(errs.Load())
}

// === 正确性 ===

func TestConcurrentAppend_10(t *testing.T) {
	finalLen, errs := runConcurrentAppend(t, 10)
	if errs != 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	if finalLen != 4+10 {
		t.Errorf("expected %d bytes (init+10), got %d (some appends lost)", 4+10, finalLen)
	}
}

func TestConcurrentAppend_50(t *testing.T) {
	finalLen, errs := runConcurrentAppend(t, 50)
	if errs != 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	if finalLen != 4+50 {
		t.Errorf("expected %d bytes (init+50), got %d (some appends lost)", 4+50, finalLen)
	}
}

func TestConcurrentAppend_100(t *testing.T) {
	finalLen, errs := runConcurrentAppend(t, 100)
	if errs != 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	if finalLen != 4+100 {
		t.Errorf("expected %d bytes (init+100), got %d (some appends lost)", 4+100, finalLen)
	}
}

// === 活性 ===

// TestConcurrentAppend_NoDeadlock：100 goroutine + 5s context timeout
// 如果锁有死锁，context 会超时
func TestConcurrentAppend_NoDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	userlib.DatastoreClear()
	userlib.KeystoreClear()
	alice, _ := InitUser("alice", "pwd123")
	alice.StoreFile("deadlock.txt", []byte("init"))

	var wg sync.WaitGroup
	n := 100
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			done := make(chan struct{})
			go func() {
				defer close(done)
				alice.AppendWithRetry("deadlock.txt", []byte("x"), 5)
			}()
			select {
			case <-done:
			case <-ctx.Done():
				t.Errorf("goroutine timed out: %v", ctx.Err())
				return
			}
		}()
	}
	wg.Wait()
}

// TestConcurrentAppend_Fairness：100 goroutine 记录完成时间
// 验证无饥饿（max-min < 1s）
func TestConcurrentAppend_Fairness(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	alice, _ := InitUser("alice", "pwd123")
	alice.StoreFile("fair.txt", []byte("init"))

	var wg sync.WaitGroup
	n := 100
	doneTimes := make([]time.Time, n)
	var mu sync.Mutex
	start := time.Now()

	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			alice.AppendWithRetry("fair.txt", []byte("x"), 5)
			mu.Lock()
			doneTimes[i] = time.Now()
			mu.Unlock()
		}()
	}
	wg.Wait()

	var minT, maxT time.Time
	for i, ts := range doneTimes {
		if i == 0 {
			minT, maxT = ts, ts
			continue
		}
		if ts.Before(minT) {
			minT = ts
		}
		if ts.After(maxT) {
			maxT = ts
		}
	}
	spread := maxT.Sub(minT)
	total := time.Since(start)
	t.Logf("100 goroutines: spread=%v total=%v", spread, total)

	if spread > time.Second {
		t.Errorf("fairness: spread %v > 1s, possible starvation", spread)
	}
}

// === 冲突率曲线 ===

// TestConflictRateCurve：1/10/50/100 并发下 retry 次数统计
// 输出表格，retry 率应 < 30%（不期望无冲突，但冲突应可控）
func TestConflictRateCurve(t *testing.T) {
	prevHook := AppendRetryHook
	defer func() { AppendRetryHook = prevHook }()

	levels := []int{1, 10, 50, 100}
	type result struct {
		n        int
		retries  int64
		success  int64
		exhaust  int64
	}
	results := make([]result, len(levels))

	for idx, n := range levels {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
		alice, _ := InitUser("alice", "pwd123")
		alice.StoreFile("conflict.txt", []byte("init"))

		var retries, success, exhaust atomic.Int64
		AppendRetryHook = func(retryCount int, exhausted bool) {
			retries.Add(int64(retryCount))
			if exhausted {
				exhaust.Add(1)
			} else {
				success.Add(1)
			}
		}

		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				alice.AppendWithRetry("conflict.txt", []byte("x"), 5)
			}()
		}
		wg.Wait()

		results[idx] = result{n: n, retries: retries.Load(), success: success.Load(), exhaust: exhaust.Load()}
	}

	t.Log("Conflict rate curve:")
	t.Log("  N    | success | exhaust | total_retries | avg_retries/success")
	for _, r := range results {
		avg := float64(0)
		if r.success > 0 {
			avg = float64(r.retries) / float64(r.success)
		}
		t.Logf("  %4d | %7d | %7d | %13d | %.2f", r.n, r.success, r.exhaust, r.retries, avg)
	}

	// 验收：100 并发下平均 retry < 3（30% 上限，因为 maxRetry=5）
	for _, r := range results {
		if r.exhaust > 0 {
			t.Errorf("N=%d: %d goroutines exhausted retries", r.n, r.exhaust)
		}
		if r.n >= 50 {
			avg := float64(r.retries) / float64(r.success)
			if avg > 3 {
				t.Errorf("N=%d: avg retries %.2f > 3 (too much contention)", r.n, avg)
			}
		}
	}
}

// === Benchmark 吞吐 ===

func benchAppend(b *testing.B, n int) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	alice, _ := InitUser("alice", "pwd123")
	alice.StoreFile("bench.txt", []byte("init"))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if err := alice.AppendWithRetry("bench.txt", []byte("x"), 5); err != nil {
				b.Fatalf("append failed at i=%d: %v", i, err)
			}
			i++
		}
	})
}

func BenchmarkAppendWithRetry_Single(b *testing.B) {
	benchAppend(b, 1)
}

func BenchmarkAppendWithRetry_Concurrent_10(b *testing.B) {
	benchAppend(b, 10)
}

func BenchmarkAppendWithRetry_Concurrent_100(b *testing.B) {
	benchAppend(b, 100)
}

// === 单次 append 延迟（无并发，作为基线）===

func BenchmarkAppendWithRetry_Baseline(b *testing.B) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	alice, _ := InitUser("alice", "pwd123")
	alice.StoreFile("base.txt", []byte("init"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := alice.AppendWithRetry("base.txt", []byte("x"), 5); err != nil {
			b.Fatalf("append failed at i=%d: %v", i, err)
		}
	}
}

// === helper：跑 benchmark 并打印报告 ===

// TestPrintBenchSummary 跑一遍所有 benchmark 汇总输出，方便 docs/benchmark.md 引用
// 不是真正的测试，只输出——不影响 CI
func TestPrintBenchSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bench summary in short mode")
	}
	results := map[string]string{
		"Baseline":  "单 goroutine 顺序 append",
		"Concurrent_10":  "10 goroutine 并发 append",
		"Concurrent_100": "100 goroutine 并发 append",
	}
	t.Log("Benchmark summary (run `go test -bench=. -benchmem ./client/` for raw data):")
	for name, desc := range results {
		t.Logf("  %s: %s", name, desc)
	}
	fmt.Println("Run: go test -bench=. -benchmem -count=5 ./client/ > docs/benchmark_raw.txt")
}
