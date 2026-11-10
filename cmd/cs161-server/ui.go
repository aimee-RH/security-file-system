package main

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

// webAssets keeps the portfolio demo self-contained in the Go binary.
//
//go:embed web/*
var webAssets embed.FS

func registerDemoUI(r *gin.Engine) {
	webRoot, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic(err)
	}

	r.StaticFS("/demo", http.FS(webRoot))
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/demo/")
	})
}
