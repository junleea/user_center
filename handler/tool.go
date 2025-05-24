package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/service"
	"user_center/worker"
)

type SetRedisReq struct {
	Option string `json:"option" form:"option"`
	Key    string `json:"key" form:"key"`
	Value  string `json:"value" form:"value"`
	Expire int    `json:"expire" form:"expire"`
}

type SetDeviceStatusReq struct {
	ID     string `json:"id" form:"id"`         //设备编码
	Status string `json:"status" form:"status"` //设备状态
}

type GetFileListReq struct {
	Type string `json:"type" form:"type"` //请求类型，1：按md5查询，2：按文件名查询;3:查询待删除文件
	Md5  string `json:"md5" form:"md5"`
}

type SendMailReq struct {
	Title   string `json:"title" form:"title"`
	Content string `json:"content" form:"content"`
	To      string `json:"to" form:"to"`
}

func SetUpToolGroup(router *gin.Engine) {
	toolGroup := router.Group("/tool")
	toolGroup.POST("/set_redis", SetRedis)
	toolGroup.POST("/get_redis", GetRedis)

	toolGroup.POST("/qq_callback", handleQQCallback)
	toolGroup.GET("/qq_auth", GetQQAuthUrl)
	toolGroup.GET("/github_auth", GetGithubAuthUrl)
	toolGroup.GET("/get_auth_url", GetThirdPartyAuthUrl)
	toolGroup.GET("/github_callback", handleGithubCallback)
	toolGroup.GET("/gitee_callback", handleGiteeCallback)
	toolGroup.GET("/third_party_callback", handleThirdPartyCallback) //统一处理第三方登录回调
	toolGroup.POST("/loginRedirect", LoginRedirect)
	//发送邮件
	toolGroup.POST("/send_mail", SendMailTool)
	//国外服务器处理请求
	toolGroup.POST("/online_server_request", HandleOnlineServerRequest)
}

type QQCallbackReq struct {
	Code  string `json:"code" form:"code"`
	State string `json:"state" form:"state"`
}

func GetQQAuthUrl(c *gin.Context) {
	//query
	uuid := c.Query("uuid")
	hType := c.Query("type")
	var resp proto.GenerateResp
	if uuid == "" || hType == "" {
		resp.Code = proto.ParameterError
		resp.Message = "uuid or hType is empty"
		c.JSON(http.StatusOK, resp)
		return
	}
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", worker.AppId)
	params.Add("state", "saw_"+hType+"_"+uuid)
	str := fmt.Sprintf("%s", params.Encode())
	loginURL := fmt.Sprintf("%s?%s", "https://graph.qq.com/oauth2.0/authorize", str)
	//c.Redirect(http.StatusFound, loginURL) //重定向到QQ登录页面
	resp.Message = "success"
	resp.Code = proto.SuccessCode
	resp.Data = loginURL
	c.JSON(http.StatusOK, resp)
}

func handleQQCallback(c *gin.Context) {
	var resp proto.GenerateResp
	resp.Code = 0
	var req QQCallbackReq
	//query参数
	if err := c.ShouldBindQuery(&req); err != nil {
		resp.Code = 1
		resp.Message = "参数错误"
		c.JSON(http.StatusOK, resp)
		return
	} else {

	}

	c.JSON(http.StatusOK, resp)
}

func SetRedis(c *gin.Context) {
	//先查看是否有权限
	id, _ := c.Get("id")
	id1 := int(id.(float64))
	user := dao.FindUserByUserID(id1)
	if user.Redis == false {
		c.JSON(http.StatusOK, gin.H{"error": "no redis Permissions", "code": proto.NoRedisPermissions, "message": "failed"})
		return
	}
	//解析请求参数
	var req SetRedisReq
	if err := c.ShouldBind(&req); err == nil {
		var code int
		var message string
		if req.Option == "list" {
			code, message = service.SetToolRedisList(req.Key, req.Value, req.Expire)
		} else if req.Option == "set" {
			code, message = service.SetToolRedisSet(req.Key, req.Value, req.Expire)
		} else if req.Option == "kv" {
			code, message = service.SetToolRedisKV(req.Key, req.Value, req.Expire)
		}
		c.JSON(http.StatusOK, gin.H{"code": code, "message": message})
	} else {
		c.JSON(http.StatusOK, gin.H{"error": "parameter error", "code": proto.ParameterError, "message": "failed"})
		return
	}
}

func GetRedis(c *gin.Context) {
	//先查看是否有权限
	id, _ := c.Get("id")
	id1 := int(id.(float64))
	user := dao.FindUserByUserID(id1)
	if user.Redis == false {
		c.JSON(http.StatusOK, gin.H{"error": "no redis Permissions", "code": proto.NoRedisPermissions, "message": "failed"})
		return
	}
	//解析请求参数
	var req SetRedisReq
	if err := c.ShouldBind(&req); err == nil {
		if req.Option == "one" {
			code, message := service.GetToolRedis(req.Key)
			req.Value = message
			c.JSON(http.StatusOK, gin.H{"code": code, "message": message, "data": req})
		} else if req.Option == "all" {
			code, message, data := service.GetAllRedis()
			c.JSON(http.StatusOK, gin.H{"code": code, "message": message, "data": data})
		}
	} else {
		c.JSON(http.StatusOK, gin.H{"error": "parameter error", "code": proto.ParameterError, "message": "failed"})
		return
	}
}

// 服务器、设备状态扫描
func ScanDeviceStatus() {
	// TODO
	// 检查设备状态
	// 如果设备状态异常, 则发送邮件通知
	devices := worker.GetRedisSetMembers("627gyf3488h")
	offline := ""
	for _, v := range devices {
		c := worker.IsContainKey("monitor_" + v)
		if c == false {
			worker.SetRedisWithExpire("monitor_"+v, "2", time.Hour*24)
			offline += v + ","
		}
	}

	if offline != "" {
		title := "设备状态异常"
		content := "设备状态异常\n设备: " + offline + "\t时间：" + time.Now().String()
		go SendMail(title, content)
	}

}

func SendMail(title, content string) {
	//捕获异常
	defer func() {
		if err := recover(); err != nil {
			fmt.Errorf("tool send mail error: %s", err)
		}
	}()
	// TODO
	// 发送邮件
	// 邮件内容
	// 邮件标题
	// 收件人
	// 发送邮件
	// 发送邮件通知
	// 发送邮件通知
	var em worker.MyEmail
	em.SmtpPassword = "nihzazdkmucnbhid"
	em.SmtpHost = "pop.qq.com:587"
	em.SmtpUserName = "354425203@qq.com"
	em.SmtpPort = 587
	em.ImapPort = 993
	err := em.Send(title, content, []string{"3236990479@qq.com", "lijun@ljsea.top"})
	if err != nil {
		fmt.Println(err)
	}
}

func SendMailTool(c *gin.Context) {
	id, _ := c.Get("id")
	id1 := int(id.(float64))

	var req SendMailReq
	if err := c.ShouldBind(&req); err == nil {
		user := dao.FindUserByUserID(id1)
		if user.ID == 0 {
			c.JSON(http.StatusOK, gin.H{"error": "user not found", "code": proto.ParameterError, "message": "failed"})
			return
		}
		//目标邮箱地址是否合法
		if !service.CheckEmail(req.To) {
			c.JSON(http.StatusOK, gin.H{"error": "email address is invalid", "code": proto.ParameterError, "message": "failed"})
			return
		}
		if req.Title == "" || req.Content == "" {
			c.JSON(http.StatusOK, gin.H{"error": "title or content is empty", "code": proto.ParameterError, "message": "failed"})
			return
		}
		//发送邮件
		if user.Role == "admin" {
			go service.SendEmail(req.To, req.Title, req.Content)
			c.JSON(http.StatusOK, gin.H{"code": proto.SuccessCode, "message": "success", "data": "mail will be sent"})
		} else {
			c.JSON(http.StatusOK, gin.H{"error": "no send mail permission", "code": proto.PermissionDenied, "message": "failed"})
		}
	} else {
		c.JSON(http.StatusOK, gin.H{"error": err.Error(), "code": proto.ParameterError, "message": "failed"})
	}

}

func handleGithubCallback(c *gin.Context) {
	var resp proto.GenerateResp
	code := c.Query("code")            //code
	stateBase64Str := c.Query("state") //state
	//解析base64
	decodedBytes, err := base64.StdEncoding.DecodeString(stateBase64Str)
	if err != nil {
		fmt.Println("Decoding error:", err)
	} else {
		decodedStr := string(decodedBytes)
		//json解析
		var state proto.ThirdPartyLoginState
		err = json.Unmarshal([]byte(decodedStr), &state)
		log.Println("handle github callback state:", decodedStr, "\tcode:", code)
		if err != nil {
			log.Println("json unmarshal error:", err)
		}
		service.DoGithubCallBack(&state, code)
	}
	resp.Code = 0
	resp.Message = "success"
	c.JSON(http.StatusOK, resp)
}

func handleGiteeCallback(c *gin.Context) {
	var resp proto.GenerateResp
	code := c.Query("code")            //code
	stateBase64Str := c.Query("state") //state
	//解析base64
	decodedBytes, err := base64.StdEncoding.DecodeString(stateBase64Str)
	if err != nil {
		fmt.Println("Decoding error:", err)
	} else {
		if code == "" || stateBase64Str == "" {
			log.Println("code or state is empty")
		} else {
			decodedStr := string(decodedBytes)
			//json解析
			var state proto.ThirdPartyLoginState
			err = json.Unmarshal([]byte(decodedStr), &state)
			if err != nil {
				log.Println("json unmarshal error:", err)
			} else {
				log.Println("handle github callback state:", decodedStr, "\tcode:", code)
				service.DoGiteeCallBack(&state, code)
			}
		}
	}
	resp.Code = 0
	resp.Message = "success"
	c.JSON(http.StatusOK, resp)
	c.Redirect(http.StatusFound, "https://sv.ljsea.top/") //重定向到登录页面
}

func GetGithubAuthUrl(c *gin.Context) {
	uuid := c.Query("uuid")
	hType := c.Query("type") //操作类型add,login
	var resp proto.GenerateResp
	if uuid == "" || hType == "" {
		resp.Code = proto.ParameterError
		resp.Message = "uuid or type is empty"
		c.JSON(http.StatusOK, resp)
		return
	} else {
		var state proto.ThirdPartyLoginState
		state.UUID = uuid
		state.Type = hType
		state.Platform = "github"
		state.Project = "saw"
		stateStr, _ := json.Marshal(state)
		//base64编码
		stateBase64Str := base64.StdEncoding.EncodeToString(stateStr)

		params := url.Values{}
		params.Add("client_id", proto.Config.GITHUB_CLIENT_ID)
		params.Add("login", uuid)
		params.Add("state", stateBase64Str)
		baseUri := "https://github.com/login/oauth/authorize"
		redirectUrl := fmt.Sprintf("%s?%s", baseUri, params.Encode())
		//c.Redirect(http.StatusFound, redirectUrl)
		resp.Message = "success"
		resp.Code = proto.SuccessCode
		resp.Data = redirectUrl
		c.JSON(http.StatusOK, resp)
	}

}

func LoginRedirect(c *gin.Context) {
	c.Redirect(http.StatusFound, "https://sv.ljsea.top/") //重定向到登录页面
}

func GetThirdPartyAuthUrl(c *gin.Context) {
	platform := c.Query("platform")
	uuid_ := c.Query("uuid")
	hType := c.Query("type") //操作类型add,login
	var resp proto.GenerateResp
	if platform == "" || uuid_ == "" || hType == "" {
		resp.Code = proto.ParameterError
		resp.Message = "platform or uuid is empty"
		c.JSON(http.StatusOK, resp)
		return
	}
	var state proto.ThirdPartyLoginState
	state.UUID = uuid_
	state.Type = hType
	state.Platform = platform
	state.Project = "SAW"
	if hType == "add" {
		//查看是否已经绑定
		token := c.Request.Header.Get("token")
		if token == "" {
			token = c.Query("token")
		}
		if token == "" {
			resp.Code = proto.ParameterError
			resp.Message = "token is empty"
			c.JSON(http.StatusOK, resp)
			return
		}
		userID, err := service.DecodeJWTToken(token)
		if err != nil {
			resp.Code = proto.ParameterError
			resp.Message = err.Error()
			c.JSON(http.StatusOK, resp)
			return
		}
		//需要将uuid绑定在该用户上
		worker.SetRedisWithExpire("user_add_platform_"+uuid_, strconv.Itoa(userID), time.Minute*9)
		state.UserID = userID
	}

	stateStr, _ := json.Marshal(state)
	stateID := uuid.NewString()
	worker.SetRedisWithExpire("state_id_"+stateID, string(stateStr), time.Minute*9)

	var respUrl string
	//base64编码
	stateBase64Str := base64.StdEncoding.EncodeToString(stateStr)
	stateBase64Str = stateID
	switch platform {
	case "qq":
		params := url.Values{}
		params.Add("response_type", "code")
		params.Add("client_id", worker.QQClientID)
		params.Add("state", stateBase64Str)
		params.Add("redirect_uri", "https://www.ljsea.top/qq_callback.php")
		str := fmt.Sprintf("%s", params.Encode())
		respUrl = fmt.Sprintf("%s?%s", proto.QQAuthorizeBaseUrl, str)
	case "github":
		params := url.Values{}
		params.Add("client_id", proto.Config.GITHUB_CLIENT_ID)
		params.Add("login", uuid_)
		params.Add("state", stateBase64Str)
		baseUri := proto.GitHuAuthorizeBaseUrl
		respUrl = fmt.Sprintf("%s?%s", baseUri, params.Encode())
	case "gitee":
		params := url.Values{}
		params.Add("client_id", proto.Config.GITEE_CLIENT_ID)
		//response_type=code
		params.Add("response_type", "code")
		params.Add("state", stateBase64Str)
		params.Add("redirect_uri", "https://uc.ljsea.top/tool/third_party_callback")
		baseUri := proto.GiteeAuthorizeBaseUrl
		respUrl = fmt.Sprintf("%s?%s", baseUri, params.Encode())
	case "google":
		params := url.Values{}
		params.Add("client_id", worker.GoogleClientID)
		params.Add("response_type", "code") //直接返回token
		redirectURL := "https://uc.ljsea.top/tool/third_party_callback"
		scope := "https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile"
		//params.Add("redirect_uri", "https://uc.ljsea.top/tool/third_party_callback")
		//params.Add("scope", "https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile")
		params.Add("state", stateBase64Str)
		baseUri := proto.GoogleAuthorizeBaseUrl
		respUrl = fmt.Sprintf("%s?%s", baseUri, params.Encode())
		respUrl = fmt.Sprintf("%s&redirect_uri=%s&scope=%s", respUrl, redirectURL, scope)
	case "facebook":
		params := url.Values{}
		params.Add("client_id", worker.FacebookClientID)
		params.Add("redirect_uri", "https://uc.ljsea.top/tool/third_party_callback")
		params.Add("response_type", "code") //直接返回token
		params.Add("state", stateBase64Str)
		respUrl = fmt.Sprintf("%s?%s", proto.FacebookAuthorizeBaseUrl, params.Encode())
	case "stackoverflow":
		params := url.Values{}
		params.Add("client_id", worker.StackOverflowClientID)
		params.Add("redirect_uri", "https://uc.ljsea.top/tool/third_party_callback")
		//params.Add("scope", "")
		params.Add("state", stateBase64Str)
		respUrl = fmt.Sprintf("%s?%s", proto.StackOverflowAuthorizeBaseUrl, params.Encode())
	case "my_gitea", "gitea":
		params := url.Values{}
		client_id := ""
		baseUrl := ""
		if platform == "my_gitea" {
			client_id = worker.MyGiteaClientID
			baseUrl = proto.MyGiteaAuthorizeBaseUrl
		} else {
			client_id = worker.GiteaClientID
			baseUrl = proto.GiteaAuthorizeBaseUrl
		}
		params.Add("client_id", client_id)
		params.Add("redirect_uri", "https://uc.ljsea.top/tool/third_party_callback")
		params.Add("response_type", "code") //返回code
		params.Add("state", stateID)
		params.Add("scope", "user")
		respUrl = fmt.Sprintf("%s?%s", baseUrl, params.Encode())
	case "microsoft":
		params := url.Values{}
		params.Add("client_id", worker.MicroSoftClientID)
		params.Add("redirect_uri", "https://uc.ljsea.top/tool/third_party_callback")
		params.Add("response_type", "code") //返回code
		params.Add("state", stateID)
		params.Add("scope", "User.Read Mail.Read")
		respUrl = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?%s", worker.MicroSoftTenantID, params.Encode())
	default:
		log.Println("platform not support:", platform)
	}
	resp.Message = "success"
	resp.Code = proto.SuccessCode
	resp.Data = respUrl
	c.JSON(http.StatusOK, resp)
}

type GetThirdPartyAddAuthUrlReq struct {
	Platform string `json:"platform" form:"platform"`
	Uuid     string `json:"uuid" form:"uuid"`
	HType    string `json:"type" form:"type"` //操作类型add,login
	//Platform string `json:"platform" form:"platform"` //操作类型add,login
}

func handleThirdPartyCallback(c *gin.Context) {
	var resp proto.GenerateResp
	code := c.Query("code")     //code
	stateID := c.Query("state") //state

	//解析base64
	//decodedBytes, err := base64.StdEncoding.DecodeString(stateBase64Str)
	//
	stateStr := worker.GetRedis("state_id_" + stateID)
	if stateStr == "" {
		log.Println("state is empty,stateID=", stateID)
	} else {
		//json解析
		//log.Println("stateStr:", stateStr, "\tcode:", code)
		var state proto.ThirdPartyLoginState
		err := json.Unmarshal([]byte(stateStr), &state)
		log.Println("handle callback state:", stateStr, "\tcode:", code)
		if err != nil {
			log.Println("json unmarshal error:", err)
		} else {
			service.DoThirdPartyCallBack(&state, code)
		}
		worker.DelRedis("state_id_" + stateID) //删除state
	}
	resp.Code = 0
	resp.Message = "success"
	c.JSON(http.StatusOK, resp)
}

func HandleOnlineServerRequest(c *gin.Context) {
	var req proto.OnlineServerReq
	var resp proto.GenerateResp
	if err := c.ShouldBind(&req); err == nil {
		log.Println("handle online server request:", req)
		respData, err2 := service.DoRequestToForeignServer(&req)
		if err2 != nil {
			resp.Code = proto.OperationFailed
			resp.Message = err2.Error()
		} else {
			resp.Code = proto.SuccessCode
			resp.Message = "success"
			resp.Data = respData
		}
	} else {
		resp.Code = proto.ParameterError
		resp.Message = "参数错误"
	}
	c.JSON(http.StatusOK, resp)
}
