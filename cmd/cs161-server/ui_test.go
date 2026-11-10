package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoUIRedirectsFromRoot(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	newAuthenticatedRouter().ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", w.Code)
	}
	if location := w.Header().Get("Location"); location != "/demo/" {
		t.Fatalf("expected /demo/ redirect, got %q", location)
	}
}

func TestDemoUIServesPortfolioPage(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/demo/", nil)
	newAuthenticatedRouter().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "VaultShare") {
		t.Fatal("expected portfolio page to contain VaultShare branding")
	}
}
