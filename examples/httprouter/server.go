package main

import (
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"

	"github.com/sbowman/cors"
)

func Hello(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")
	_, _ = ctx.Write([]byte("{\"hello\": \"world\"}"))
}

func main() {
	r := router.New()
	r.GET("/", Hello)

	handler := cors.Default().Handler(r.Handler)

	fasthttp.ListenAndServe(":8080", handler)
}
