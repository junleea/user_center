package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	//"net/http"
)

// 跨域访问：cross  origin resource share
func CrosHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 设置允许访问的域名，这里使用*表示允许所有域名访问
		// 注意：如果需要携带凭证（如cookies），则不能使用*，必须指定具体的域名
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")

		// 设置允许的请求方法
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		// 设置允许的请求头
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Authorization, Content-Type, Accept, token")

		// 设置允许前端获取的响应头
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers")

		// 设置预检请求的缓存时间（秒）
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		// 设置是否允许携带凭证
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "false")

		// 设置返回格式
		c.Set("content-type", "application/json")

		// 处理预检请求
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		// 继续处理请求
		c.Next()
	}
}
