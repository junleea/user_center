package worker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	mrand "math/rand"
	"time"
)

func GetRandomString(l int) string {
	str := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	var result []byte
	for i := 0; i < l; i++ {
		result = append(result, bytes[mrand.Intn(len(bytes))])
	}
	return string(result)
}

func GetCurrentTimestamp() int64 {
	// 获取当前时间戳
	return time.Now().Unix()
}

// AESEncrypt 函数使用AES-GCM算法对明文进行加密
func AESEncrypt(plaintext []byte, key []byte) (string, error) {
	// 创建AES加密块
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 创建GCM模式的加密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 生成随机的nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 执行加密操作
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// 将加密结果转换为Base64编码字符串
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AESDecrypt 函数使用AES-GCM算法对密文进行解密
func AESDecrypt(ciphertext string, key []byte) ([]byte, error) {
	// 将Base64编码的密文转换为字节切片
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	// 创建AES加密块
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建GCM模式的解密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 提取nonce和真正的密文
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("密文长度过短")
	}
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]

	// 执行解密操作
	return gcm.Open(nil, nonce, ciphertextBytes, nil)
}
