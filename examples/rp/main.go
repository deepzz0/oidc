// Package main provides ...
package main

import "github.com/gin-gonic/gin"

func main() {
	e := gin.Default()

	e.GET("/homepage", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.Writer.WriteString(`
<iframe id="inlineFrameExample"
    title="Inline Frame Example"
    width="300"
    height="200"
	src="http://localhost:8080/oidc/check-session">
</iframe>
		`)
	})
	e.Run(":8090")
}
