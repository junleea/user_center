package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var client *http.Client

// 初始化
func InitReq() {
	client = &http.Client{}
}

// 发起post请求
func Post(url string, bodyType string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	req.Body = io.NopCloser(strings.NewReader(body))
	return client.Do(req)
}

// 发送到机器人
func SendToRobot(url string, body string) (map[string]interface{}, error) {
	resp, err := Post(url, "application/json", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	m := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// 生成补全的函数
func GenerateCompletion(url, prompt string, model string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client_ := &http.Client{}
	resp, err := client_.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func DoPostRequestJSON(url string, jsonData []byte, headers map[string]string) (error, []byte) {
	httpClient := &http.Client{}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("SyncDataFromMasterReq2 error:", r)
		}
	}()

	//从接口获取数据
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0")
	//设置header
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	//传输数据
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	//获取数据
	resp, err := httpClient.Do(req)
	if err != nil {
		return err, nil
	}
	defer resp.Body.Close()
	//解析数据
	responseBod, err := io.ReadAll(resp.Body)
	if err != nil {
		return err, nil
	}
	return err, responseBod
}

func DoPostRequestForm(url string, jsonData []byte, headers map[string]string) (error, []byte) {
	httpClient := &http.Client{}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("SyncDataFromMasterReq2 error:", r)
		}
	}()

	// 创建一个新的 buffer 用于存储 multipart/form-data 请求体
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	// 修改 data 类型为 map[string]interface{} 以支持不同类型的值
	var data map[string]interface{}
	err2 := json.Unmarshal(jsonData, &data)
	if err2 != nil {
		log.Println("do post json unmarshal error:", err2)
		return err2, nil
	}

	var err error
	for k, v := range data {
		switch val := v.(type) {
		case bool:
			// 处理布尔类型的值
			err = writer.WriteField(k, strconv.FormatBool(val))
		case string:
			// 处理字符串类型的值
			err = writer.WriteField(k, val)
		default:
			// 其他类型可以根据需要扩展处理逻辑
			log.Printf("Unsupported type for field %s: %T\n", k, v)
			continue
		}
		if err != nil {
			log.Println("write field error:", err)
			return err, nil
		}
	}

	// 关闭 writer 以完成请求体的构建
	err = writer.Close()
	if err != nil {
		return err, nil
	}

	// 创建 POST 请求
	req, err := http.NewRequest("POST", url, body)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0")
	if err != nil {
		return err, nil
	}

	// 设置 Content-Type 为 multipart/form-data，并带上 boundary
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// 设置其他自定义请求头
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 发送请求
	resp, err := httpClient.Do(req)
	if err != nil {
		return err, nil
	}
	defer resp.Body.Close()

	// 读取响应体
	responseBod, err := io.ReadAll(resp.Body)
	if err != nil {
		return err, nil
	}

	return nil, responseBod
}

func DoPostRequestFormUrlEncoded(url_ string, jsonData []byte, headers map[string]string) (error, []byte) {
	httpClient := &http.Client{}
	defer func() {
		if r := recover(); r != nil {
			log.Println("SyncDataFromMasterReq2 error:", r)
		}
	}()

	// 解析 JSON 数据
	var data map[string]interface{}
	err := json.Unmarshal(jsonData, &data)
	if err != nil {
		log.Println("do post json unmarshal error:", err)
		return err, nil
	}

	// 创建 url.Values 来存储请求参数
	reqData := url.Values{}
	for k, v := range data {
		switch val := v.(type) {
		case bool:
			// 处理布尔类型的值
			reqData.Set(k, strconv.FormatBool(val))
		case string:
			// 处理字符串类型的值
			reqData.Set(k, val)
		default:
			// 其他类型可以根据需要扩展处理逻辑
			log.Printf("Unsupported type for field %s: %T\n", k, v)
			continue
		}
	}

	// 将 url.Values 编码为 URL 编码的格式
	encodedData := reqData.Encode()

	// 创建 POST 请求
	req, err := http.NewRequest("POST", url_, bytes.NewBufferString(encodedData))
	if err != nil {
		return err, nil
	}

	// 设置请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 设置其他自定义请求头
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 发送请求
	resp, err := httpClient.Do(req)
	if err != nil {
		return err, nil
	}
	defer resp.Body.Close()

	// 读取响应体
	responseBod, err := io.ReadAll(resp.Body)
	if err != nil {
		return err, nil
	}

	return nil, responseBod
}

func DoGetRequest(url string, headers map[string]string) (error, []byte) {
	httpClient := &http.Client{}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("SyncDataFromMasterReq2 error:", r)
		}
	}()

	//从接口获取数据
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0")
	if err != nil {
		return err, nil
	}
	//设置header
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	//传输数据
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	//获取数据
	resp, err := httpClient.Do(req)
	if err != nil {
		return err, nil
	}
	defer resp.Body.Close()
	//解析数据
	responseBod, err := io.ReadAll(resp.Body)
	if err != nil {
		return err, nil
	}
	return err, responseBod
}
