package worker

import (
	"math/rand"
	"time"
)

func GetRandomString(l int) string {
	str := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	var result []byte
	for i := 0; i < l; i++ {
		result = append(result, bytes[rand.Intn(len(bytes))])
	}
	return string(result)
}

func GetCurrentTimestamp() int64 {
	// 获取当前时间戳
	return time.Now().Unix()
}
