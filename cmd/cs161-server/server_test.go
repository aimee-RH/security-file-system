package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	userlib "github.com/cs161-staff/project2-userlib"
)

// 接缝 1：HTTP 路由 + 请求体解析
func TestAPIUserInitSuccess(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	body, _ := json.Marshal(APIRequest{Username: "alice", Password: "pwd123"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/users/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	newRouter().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response json: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp)
	}
}

// 接缝 2：handler 调用底层 + 鉴权失败返回 401
func TestAPIFileStoreWithoutAuth(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	body, _ := json.Marshal(APIRequest{Username: "alice", Password: "wrong"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/files/store", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	newRouter().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (user not found), got %d", w.Code)
	}
}

// 接缝 2：完整流程 user init + file store + file load
func TestAPIFileStoreAndLoad(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	// init user
	body, _ := json.Marshal(APIRequest{Username: "alice", Password: "pwd123"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/users/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	newRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("user init failed: %d", w.Code)
	}

	// store file
	storeBody, _ := json.Marshal(APIRequest{Username: "alice", Password: "pwd123", Filename: "test.txt", Data: "hello world"})
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/files/store", bytes.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	newRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("file store failed: %d; body=%s", w.Code, w.Body.String())
	}

	// load file
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/files/load?username=alice&password=pwd123&filename=test.txt", nil)
	newRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("file load failed: %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("hello world")) {
		t.Errorf("expected body to contain 'hello world', got %s", w.Body.String())
	}
}

// 接缝 3：错误处理 - 无效 JSON
func TestAPIInvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/users/init", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	newRouter().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid json, got %d", w.Code)
	}
}

// 接缝 3：未知路由 404
func TestAPINotFound(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/nonexistent", nil)
	newRouter().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// 接缝 3：file load 缺参数 400
func TestAPIFileLoadMissingParams(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/files/load?username=alice", nil)
	newRouter().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing params, got %d", w.Code)
	}
}
