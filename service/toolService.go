package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"log"
	"regexp"
	"strconv"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker"
)

func SetToolRedisList(key string, value string, expire int) (code int, message string) {
	if expire == 0 {
		if worker.PushRedisList(key, value) {
			return proto.SuccessCode, "success"
		} else {
			return proto.OperationFailed, "push redis list failed"
		}
	} else if expire > 0 {
		if worker.PushRedisListWithExpire(key, value, time.Duration(expire)) {
			return proto.SuccessCode, "success"
		} else {
			return proto.OperationFailed, "push redis list with expire failed"
		}
	} else {
		return proto.ParameterError, "expire time can not be negative"
	}
}

func SetToolRedisSet(key string, value string, expire int) (code int, message string) {
	if expire == 0 {
		if worker.SetRedis(key, value) {
			return proto.SuccessCode, "success"
		} else {
			return proto.OperationFailed, "set redis failed"
		}
	} else if expire > 0 {
		if worker.SetRedisWithExpire(key, value, time.Duration(expire)) {
			return proto.SuccessCode, "success"
		} else {
			return proto.OperationFailed, "set redis with expire failed"
		}
	} else {
		return proto.ParameterError, "expire time can not be negative"
	}
}

func SetToolRedisKV(key string, value string, expire int) (code int, message string) {
	if expire == 0 {
		if worker.SetRedis(key, value) {
			return proto.SuccessCode, "success"
		} else {
			return proto.OperationFailed, "set redis failed"
		}
	} else if expire > 0 {
		if worker.SetRedisWithExpire(key, value, time.Duration(expire)) {
			return proto.SuccessCode, "success"
		} else {
			return proto.OperationFailed, "set redis with expire failed"
		}
	} else {
		return proto.ParameterError, "expire time can not be negative"
	}
}

func GetToolRedis(key string) (code int, message string) {
	val := worker.GetRedis(key)
	if val == "" {
		return proto.OperationFailed, "get redis failed"
	} else {
		return proto.SuccessCode, val
	}
}

func GetAllRedis() (code int, msg string, data []worker.RedisInfo) {
	data, err := worker.GetAllRedisInfo()
	if err != nil {
		return proto.OperationFailed, err.Error(), nil
	}
	return proto.SuccessCode, "success", data
}

func SendEmail(email, subject, body string) {
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
	err := em.Send(subject, body, []string{email})
	if err != nil {
		fmt.Println("send mail error:", err)
	}
}

// 地址校验
func CheckEmail(email string) bool {
	//正则表达式判断是否是邮箱
	pattern := `^([a-zA-Z0-9_-])+@([a-zA-Z0-9_-])+(.[a-zA-Z0-9_-])+$`
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}

// 解析jwt内容
func DecodeJWTToken(tokenStr string) (int, error) {
	//解析jwt
	// 使用加密secret 解析 JWT 令牌
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return proto.SigningKey, nil
	})
	if err != nil {
		return 0, err
	}
	// 验证令牌
	if !token.Valid {
		return 0, fmt.Errorf("invalid token")
	}
	// 获取用户ID
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("invalid token claims")
	}
	userID, ok := claims["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("invalid token claims")
	}
	return int(userID), nil
}

// 生成token
func GenerateJWTToken(userID int, userName string) (string, error) {
	//创建token
	claims := jwt.MapClaims{
		"id":       userID,
		"username": userName,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(proto.SigningKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func DoGiteeCallBack(state *proto.ThirdPartyLoginState, code string) {
	//获取Access Token
	resp, err := worker.GetGiteeAccessTokenByCode(code, "https://pm.ljsea.top/tool/third_party_callback", proto.Config.GITEE_CLIENT_ID, proto.Config.GITEE_CLIENT_SECRET)
	if err != nil {
		log.Println("get gitee access token error:", err)
		return
	}
	if resp.AccessToken == "" {
		log.Println("get gitee access token is empty")
		log.Println("get gitee access token error:", resp)
		return
	}
	log.Println("get gitee access token:", resp.AccessToken)
	//获取用户信息
	userInfo, err := worker.GetGiteeUserInfo(resp.AccessToken)
	if err != nil {
		log.Println("get gitee user info error:", err)
		return
	}
	log.Println("get gitee user info:", userInfo)
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	HandleThirdPartyLoginStatus(state, &thirdPartyLoginStatus, &userInfo)
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Println("do handle gitee callback success, third party login status:", string(thirdPartyLoginStatusStr))
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

func DoGogsCallBack(state *proto.ThirdPartyLoginState, code string) {
	//获取Access Token
	resp, err := worker.GetGiteeAccessTokenByCode(code, "https://pm.ljsea.top/tool/gitee_callback", proto.Config.GITEE_CLIENT_ID, proto.Config.GITEE_CLIENT_SECRET)
	if err != nil {
		log.Println("get gitee access token error:", err)
		return
	}
	if resp.AccessToken == "" {
		log.Println("get gitee access token is empty")
		log.Println("get gitee access token error:", resp)
		return
	}
	log.Println("get gitee access token:", resp.AccessToken)
	//获取用户信息
	userInfo, err := worker.GetGiteeUserInfo(resp.AccessToken)
	if err != nil {
		log.Println("get gitee user info error:", err)
		return
	}
	log.Println("get gitee user info:", userInfo)
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	HandleThirdPartyLoginStatus(state, &thirdPartyLoginStatus, &userInfo)
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Println("do handle gitee callback success, third party login status:", string(thirdPartyLoginStatusStr))
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

// 处理第三方登录状态
func HandleThirdPartyLoginStatus(state *proto.ThirdPartyLoginState, thirdPartyLoginStatus *proto.ThirdPartyLoginStatus, userInfo *proto.GitHubUserInfo) {
	if state.Type == "login" {
		//根据第三方平台查找用户
		thirdPartyUserInfoList := dao.FindThirdPartyUserInfoByThirdPartyID(strconv.Itoa(userInfo.UserID))
		if thirdPartyUserInfoList == nil || len(thirdPartyUserInfoList) == 0 {
			thirdPartyLoginStatus.Status = proto.ThirdPartyUserNotBinded //未绑定用户
		} else {
			thirdPartyUserInfo := thirdPartyUserInfoList[0]
			//获取用户信息
			user := GetUserByIDWithCache(thirdPartyUserInfo.UserID)
			if user.ID == 0 {
				thirdPartyLoginStatus.Status = proto.ThirdPartyUserNotBinded
				log.Println("get user by id error")
			} else {
				//成功
				thirdPartyLoginStatus.Status = proto.SuccessCode
				thirdPartyLoginStatus.UserInfo.UserID = int(user.ID)
				thirdPartyLoginStatus.UserInfo.Username = user.Name
				thirdPartyLoginStatus.UserInfo.Email = user.Email
				thirdPartyLoginStatus.UserInfo.Token, _ = GenerateJWTToken(int(user.ID), user.Name)
			}
		}
	} else if state.Type == "add" {
		//根据第三方平台查找用户
		thirdPartyUserInfoList := dao.FindThirdPartyUserInfoByThirdPartyID(strconv.Itoa(userInfo.UserID))
		if thirdPartyUserInfoList != nil && len(thirdPartyUserInfoList) > 0 {
			thirdPartyLoginStatus.Status = 3 //已绑定用户
		} else {
			userIDStr := worker.GetRedis("user_add_platform_" + state.UUID)
			if userIDStr == "" {
				log.Println("user id is empty")
				thirdPartyLoginStatus.Status = 2 //未绑定用户
			} else {
				//字符串转int
				userID, _ := strconv.Atoi(userIDStr)
				//根据用户ID获取用户信息
				user := GetUserByIDWithCache(userID)
				if user.ID == 0 {
					thirdPartyLoginStatus.Status = 4 //添加用户信息错误
					log.Println("get user by id error")
				} else {
					//需要创建数据库记录
					data := dao.ThirdPartyUserInfo{UserID: userID, ThirdPartyID: strconv.Itoa(userInfo.UserID), ThirdPartyPlatform: state.Platform, ThirdPartyUserAvatar: userInfo.AvatarUrl, ThirdPartyUserName: userInfo.LoginUserName, ThirdPartyUserUrl: userInfo.Url}
					uid := dao.CreateThirdPartyUserInfoV2(&data)
					if uid == 0 {
						log.Println("create third party user info error")
						thirdPartyLoginStatus.Status = proto.OperationFailed //操作错误
					} else {
						//成功
						thirdPartyLoginStatus.Status = proto.SuccessCode
						thirdPartyLoginStatus.UserInfo.UserID = int(user.ID)
						thirdPartyLoginStatus.UserInfo.Username = user.Name
						thirdPartyLoginStatus.UserInfo.Email = user.Email
						thirdPartyLoginStatus.UserInfo.Token, _ = GenerateJWTToken(int(user.ID), user.Name)
					}
				}
			}
		}
	} else {
		log.Println("DoGithubCallBack state type error:", state.Type)
		thirdPartyLoginStatus.Status = proto.ParameterError //参数错误
	}
	//更新userInfo到数据库
	err := dao.UpdateThirdPartyUserInfoByThirdPartyID(strconv.Itoa(userInfo.UserID), state.Platform, userInfo.LoginUserName, userInfo.AvatarUrl, userInfo.Url)
	if err != nil {
		log.Println("update third party user info error:", err)
	}
}

func HandleThirdPartyLoginStatusV2(state *proto.ThirdPartyLoginState, thirdPartyLoginStatus *proto.ThirdPartyLoginStatus, userInfo *proto.ThirdPartyUserInfo) {
	if state.Type == "login" {
		//根据第三方平台查找用户
		thirdPartyUserInfoList := dao.FindThirdPartyUserInfoByThirdPartyID(userInfo.UserID)
		if thirdPartyUserInfoList == nil || len(thirdPartyUserInfoList) == 0 {
			thirdPartyLoginStatus.Status = proto.ThirdPartyUserNotBinded //未绑定用户
		} else {
			thirdPartyUserInfo := thirdPartyUserInfoList[0]
			//获取用户信息
			user := GetUserByIDWithCache(thirdPartyUserInfo.UserID)
			if user.ID == 0 {
				thirdPartyLoginStatus.Status = proto.ThirdPartyUserNotBinded
				log.Println("get user by id error")
			} else {
				//成功
				thirdPartyLoginStatus.Status = proto.SuccessCode
				thirdPartyLoginStatus.UserInfo.UserID = user.ID
				thirdPartyLoginStatus.UserInfo.Username = user.Name
				thirdPartyLoginStatus.UserInfo.Email = user.Email
				thirdPartyLoginStatus.UserInfo.AccessToken, thirdPartyLoginStatus.UserInfo.AccessToken, _ = GenerateAuthTokens(user)
			}
		}
	} else if state.Type == "add" {
		//根据第三方平台查找用户
		thirdPartyUserInfoList := dao.FindThirdPartyUserInfoByThirdPartyID(userInfo.UserID)
		if thirdPartyUserInfoList != nil && len(thirdPartyUserInfoList) > 0 {
			thirdPartyLoginStatus.Status = 3 //已绑定用户
		} else {
			userIDStr := worker.GetRedis("user_add_platform_" + state.UUID)
			if userIDStr == "" {
				log.Println("user id is empty")
				thirdPartyLoginStatus.Status = 2 //未绑定用户
			} else {
				//字符串转int
				userID, _ := strconv.Atoi(userIDStr)
				//根据用户ID获取用户信息
				user := GetUserByIDWithCache(userID)
				if user.ID == 0 {
					thirdPartyLoginStatus.Status = 4 //添加用户信息错误
					log.Println("get user by id error")
				} else {
					//需要创建数据库记录
					data := dao.ThirdPartyUserInfo{UserID: userID, ThirdPartyID: userInfo.UserID, ThirdPartyPlatform: state.Platform, ThirdPartyUserAvatar: userInfo.Avatar, ThirdPartyUserName: userInfo.Name, ThirdPartyUserUrl: userInfo.Url, ThirdPartyEmail: userInfo.Email}
					uid := dao.CreateThirdPartyUserInfoV2(&data)
					if uid == 0 {
						log.Println("create third party user info error")
						thirdPartyLoginStatus.Status = proto.OperationFailed //操作错误
					} else {
						//成功
						thirdPartyLoginStatus.Status = proto.SuccessCode
						thirdPartyLoginStatus.UserInfo.UserID = user.ID
						thirdPartyLoginStatus.UserInfo.Username = user.Name
						thirdPartyLoginStatus.UserInfo.Email = user.Email
						thirdPartyLoginStatus.UserInfo.AccessToken, thirdPartyLoginStatus.UserInfo.AccessToken, _ = GenerateAuthTokens(user)
					}
				}
			}
		}
	} else {
		log.Println("DoGithubCallBack state type error:", state.Type)
		thirdPartyLoginStatus.Status = proto.ParameterError //参数错误
	}
	//更新userInfo到数据库
	err := dao.UpdateThirdPartyUserInfoByThirdPartyID(userInfo.UserID, state.Platform, userInfo.Name, userInfo.Avatar, userInfo.Url)
	if err != nil {
		log.Println("update third party user info error:", err)
	}
}

func DoThirdPartyCallBack(state *proto.ThirdPartyLoginState, code string) {
	switch state.Platform {
	case "github":
		DoGithubCallBack(state, code)
	case "gitee":
		DoGiteeCallBack(state, code)
	case "qq":
		DoQQCallBack(state, code)
	case "gogs":
		// TODO
		log.Println("DoThirdPartyCallBack gogs error:", state.Platform)
	case "google":
		DoGoogleCallBack(state, code)
	case "facebook":
		DoFaceBookCallBack(state, code)
	case "stackoverflow":
		DoStackoverflowCallBack(state, code)
	case "my_gitea", "gitea":
		DoGiteaCallBack(state, code)
	case "microsoft":
		DoMicroSoftCallBack(state, code)
	default:
		log.Println("DoThirdPartyCallBack platform error:", state.Platform)
	}
}

func DoGithubCallBack(state *proto.ThirdPartyLoginState, code string) {
	//获取Access Token
	resp, err := worker.ExchangeCodeForAccessTokenGithub(proto.Config.GITHUB_CLIENT_ID, proto.Config.GITHUB_CLIENT_SECRET, code, "")
	if err != nil {
		log.Println("get github access token error:", err)
		return
	}
	if resp.AccessToken == "" {
		log.Println("get github access token is empty")
		return
	}
	log.Println("get github access token:", resp.AccessToken)
	//获取用户信息
	userInfo, err := worker.GetGitHubUserInfoV2(resp.AccessToken)
	if err != nil {
		log.Println("get github user info error:", err)
		return
	}
	log.Println("get github user info:", userInfo)

	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	HandleThirdPartyLoginStatus(state, &thirdPartyLoginStatus, &userInfo) //处理第三方登录状态
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Println("do handle github callback success, third party login status:", string(thirdPartyLoginStatusStr))
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

func DoGoogleCallBack(state *proto.ThirdPartyLoginState, code string) {
	//根据code获取Access Token
	tokenResp, err := worker.GetGoogleAccessTokenByCode(code, "https://pm.ljsea.top/tool/third_party_callback", worker.GoogleClientID, proto.Config.GoogleClientSecret)

	if tokenResp.AccessToken == "" {
		log.Println("get google access token is empty")
		return
	}
	log.Println("get google access token:", tokenResp)
	//获取用户信息
	userInfo, err := worker.GetGoogleUserInfo(tokenResp.AccessToken)
	if err != nil {
		log.Println("get google user info error:", err)
		return
	}
	log.Println("get google user info:", userInfo)
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	thirdPartyUserInfo := proto.ThirdPartyUserInfo{UserID: userInfo.ID, Name: userInfo.Name, Avatar: userInfo.Picture, Email: userInfo.Email}
	HandleThirdPartyLoginStatusV2(state, &thirdPartyLoginStatus, &thirdPartyUserInfo)
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Println("do handle google callback success, third party login status:", string(thirdPartyLoginStatusStr))
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

func DoFaceBookCallBack(state *proto.ThirdPartyLoginState, code string) {
	//根据code获取Access Token
	tokenResp, err := worker.GetFacebookAccessTokenByCode(code, "https://pm.ljsea.top/tool/third_party_callback", worker.FacebookClientID, proto.Config.FacebookClientSecret)

	if tokenResp.AccessToken == "" {
		log.Println("get facebook access token is empty")
		return
	}
	log.Println("get facebook access token:", tokenResp)
	//获取用户信息
	userInfo, err := worker.GetFaceBookUserInfo(tokenResp.AccessToken)
	if err != nil {
		log.Println("get facebook user info error:", err)
		return
	}
	log.Println("get facebook user info:", userInfo)
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	thirdPartyUserInfo := proto.ThirdPartyUserInfo{UserID: userInfo.ID, Name: userInfo.Name, Avatar: "", Email: ""}
	HandleThirdPartyLoginStatusV2(state, &thirdPartyLoginStatus, &thirdPartyUserInfo)
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Println("do handle facebook callback success, third party login status:", string(thirdPartyLoginStatusStr))
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

func DoStackoverflowCallBack(state *proto.ThirdPartyLoginState, code string) {
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	var userInfo proto.StackoverflowUserInfo
	thirdPartyLoginStatus.Type = state.Platform
	//根据code获取Access Token
	tokenResp, err := worker.GetStackoverflowAccessTokenByCode(code, "https://pm.ljsea.top/tool/third_party_callback", worker.StackOverflowClientID, proto.Config.StackOverflowClientSecret)
	if tokenResp.AccessToken == "" {
		log.Println("get Stackoverflow access token is empty")
		thirdPartyLoginStatus.Status = proto.ParameterError
	} else {
		log.Println("get Stackoverflow access token:", tokenResp)
		//获取用户信息
		userInfoResp, err2 := worker.GetStackoverflowUserInfo(tokenResp.AccessToken)
		if err2 != nil {
			log.Println("get Stackoverflow user info error:", err)
			thirdPartyLoginStatus.Status = proto.ParameterError
		} else {
			log.Println("get Stackoverflow user info:", userInfoResp)
			if userInfoResp.Items != nil && len(userInfoResp.Items) > 0 {
				userInfo = userInfoResp.Items[0]
				thirdPartyUserInfo := proto.ThirdPartyUserInfo{UserID: strconv.Itoa(userInfo.UserID), Name: userInfo.DisplayName, Avatar: userInfo.ProfileImage, Email: ""}
				HandleThirdPartyLoginStatusV2(state, &thirdPartyLoginStatus, &thirdPartyUserInfo)
				thirdPartyLoginStatus.Status = proto.SuccessCode
			} else {
				log.Println("get Stackoverflow user info is empty")
				thirdPartyLoginStatus.Status = proto.ParameterError
			}
		}
	}
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Println("do handle Stackoverflow callback success, third party login status:", string(thirdPartyLoginStatusStr))
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

func DoQQCallBack(state *proto.ThirdPartyLoginState, code string) {
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	//根据code获取Access Token
	tokenResp, err := worker.GetQQAccessTokenByCode(code, "https://www.ljsea.top/qq_callback.php", worker.QQClientID, proto.Config.QQClientSecret)
	if tokenResp.AccessToken == "" {
		log.Println("get QQ access token is empty")
		thirdPartyLoginStatus.Status = proto.ParameterError
	} else {
		log.Println("get QQ access token:", tokenResp)
		//获取用户信息
		userInfo, err2 := worker.GetQQUserInfo(tokenResp.AccessToken)
		if err2 != nil {
			log.Println("get QQ user info error:", err)
			thirdPartyLoginStatus.Status = proto.ParameterError
		} else {
			log.Println("get QQ user info:", userInfo)
			thirdPartyUserInfo := proto.ThirdPartyUserInfo{UserID: userInfo.OpenID, Name: userInfo.Nickname, Avatar: userInfo.Figureurl, Email: ""}
			HandleThirdPartyLoginStatusV2(state, &thirdPartyLoginStatus, &thirdPartyUserInfo)
			thirdPartyLoginStatus.Status = proto.SuccessCode
		}
	}
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Println("do handle Stackoverflow callback success, third party login status:", string(thirdPartyLoginStatusStr))
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

// 国外服务器处理国内服务器要请求外网的请求
func DoRequestToForeignServer(req *proto.OnlineServerReq) (proto.OutlineServerResp, error) {
	var resp proto.OutlineServerResp
	resp.Request = *req
	switch req.Type {
	case "get":
		headers := make(map[string]string)
		for _, v := range req.Header {
			headers[v.Key] = v.Value
		}
		err2, respBytes := worker.DoGetRequest(req.Url, headers)
		if err2 != nil {
			log.Println("DoRequestToForeignServer get error:", err2)
			return resp, err2
		}
		resp.Response.Response = string(respBytes)
	case "post":
		headers := make(map[string]string)
		for _, v := range req.Header {
			headers[v.Key] = v.Value
		}
		dataBytes, err := json.Marshal(req.Data)
		if err != nil {
			log.Println("DoRequestToForeignServer post error:", err)
			break
		}
		var err2 error
		var respBytes []byte
		if req.PostType == "json" {
			err2, respBytes = worker.DoPostRequestJSON(req.Url, dataBytes, headers)
		} else if req.PostType == "form" {
			err2, respBytes = worker.DoPostRequestForm(req.Url, dataBytes, headers)
		} else if req.PostType == "form-url-encoded" {
			err2, respBytes = worker.DoPostRequestFormUrlEncoded(req.Url, dataBytes, headers)
		} else {
			log.Println("DoRequestToForeignServer post type error:", req.PostType)
			return resp, errors.New("request post type error")
		}
		if err2 != nil {
			log.Println("DoRequestToForeignServer get error:", err2)
			return resp, err2
		}
		resp.Response.Response = string(respBytes)
	default:
		log.Println("DoRequestToForeignServer type error:", req.Type)
		return resp, errors.New("request type error")
	}
	return resp, nil

}

func DoGiteaCallBack(state *proto.ThirdPartyLoginState, code string) {
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	//根据code获取Access Token
	var baseDomain string
	var clientID string
	var clientSecret string
	if state.Platform == "my_gitea" {
		baseDomain = "https://gogs.ljsea.top"
		clientID, clientSecret = worker.MyGiteaClientID, proto.Config.MyGiteaClientSecret
	} else {
		baseDomain = "https://gitea.com"
		clientID, clientSecret = worker.GiteaClientID, proto.Config.GITEA_CLIENT_SECRET
	}
	tokenResp, _ := worker.GetGiteaAccessTokenByCode(baseDomain, code, "https://pm.ljsea.top/tool/third_party_callback", clientID, clientSecret)
	//if err != nil {
	//	log.Printf("get %s access token error:%v\n", state.Platform, err)
	//	thirdPartyLoginStatus.Status = proto.ParameterError
	//	return
	//}
	if tokenResp.AccessToken == "" {
		log.Printf("get %s access token is empty,token resp:%v\n", state.Platform, tokenResp)
		thirdPartyLoginStatus.Status = proto.ParameterError
	} else {
		log.Printf("get %s access token:%v\n", state.Platform, tokenResp.AccessToken)
		//获取用户信息
		userInfoResp, err2 := worker.GetGiteaUserInfo(baseDomain, tokenResp.AccessToken)
		if err2 != nil {
			log.Printf("get %s user info error:%v\n", state.Platform, err2)
			thirdPartyLoginStatus.Status = proto.ParameterError
		} else {
			log.Printf("get %s user info:%v\n", state.Platform, userInfoResp)
			thirdPartyUserInfo := proto.ThirdPartyUserInfo{UserID: userInfoResp.Sub, Name: userInfoResp.Name, Avatar: userInfoResp.Picture, Email: userInfoResp.Email}
			HandleThirdPartyLoginStatusV2(state, &thirdPartyLoginStatus, &thirdPartyUserInfo)
			thirdPartyLoginStatus.Status = proto.SuccessCode
		}
	}
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Printf("do handle %s callback success, third party login status: %v\n", state.Platform, thirdPartyLoginStatus)
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}

func DoMicroSoftCallBack(state *proto.ThirdPartyLoginState, code string) {
	var thirdPartyLoginStatus proto.ThirdPartyLoginStatus
	thirdPartyLoginStatus.Type = state.Platform
	//根据code获取Access Token
	tokenResp, _ := worker.GetMicroSoftAccessTokenByCode(code, "https://pm.ljsea.top/tool/third_party_callback", worker.MicroSoftClientID, proto.Config.MICROSOFT_CLIENT_SECRET)
	//if err != nil {
	//	log.Printf("get %s access token error:%v\n", state.Platform, err)
	//	thirdPartyLoginStatus.Status = proto.ParameterError
	//	return
	//}
	if tokenResp.AccessToken == "" {
		log.Printf("get %s access token is empty,token resp:%v\n", state.Platform, tokenResp)
		thirdPartyLoginStatus.Status = proto.ParameterError
	} else {
		log.Printf("get %s access token:%v\n", state.Platform, tokenResp.AccessToken)
		//获取用户信息
		userInfoResp, err2 := worker.GetMicroSoftUserInfo(tokenResp.AccessToken)
		if err2 != nil {
			log.Printf("get %s user info error:%v\n", state.Platform, err2)
			thirdPartyLoginStatus.Status = proto.ParameterError
		} else {
			log.Printf("get %s user info:%v\n", state.Platform, userInfoResp)
			thirdPartyUserInfo := proto.ThirdPartyUserInfo{UserID: userInfoResp.ID, Name: userInfoResp.DisplayName, Avatar: "", Email: ""}
			HandleThirdPartyLoginStatusV2(state, &thirdPartyLoginStatus, &thirdPartyUserInfo)
			thirdPartyLoginStatus.Status = proto.SuccessCode
		}
	}
	//更新redis中的第三方登录状态
	thirdPartyLoginStatusStr, _ := json.Marshal(thirdPartyLoginStatus)
	log.Printf("do handle %s callback success, third party login status: %v\n", state.Platform, thirdPartyLoginStatus)
	worker.SetRedisWithExpire(state.UUID, string(thirdPartyLoginStatusStr), time.Minute*10)
}
