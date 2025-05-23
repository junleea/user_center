package handler

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"net/http"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/service"
	"user_center/worker"
)

func SetUpUserGroup(router *gin.Engine) {
	userGroup := router.Group("/user")
	userGroup.POST("/register", registerHandlerV2)
	userGroup.POST("/register_code", handleRegisterCode) //注册验证码
	userGroup.POST("/login", loginHandler)
	userGroup.POST("/uuid", GetScanUUID)
	userGroup.POST("/gqr", GetQRStatus)
	userGroup.POST("/sqr", SetQRStatus)
	userGroup.POST("/confirm", ConfirmQRLogin)
	userGroup.POST("/search", SearchHandler)
	userGroup.POST("/info", GetUserInfo)
	userGroup.POST("/update", UpdateUserInfo)
	userGroup.POST("/delete", DeleteUser)
	userGroup.POST("/reset", ResetPassword)
	userGroup.GET("/oAuth", LoginOAuth) //第三方登录
	userGroup.GET("/oAuth_uuid", GetOAuthUUID)
	userGroup.POST("/third_party_login_list", GetThirdPartyLoginList)    //获取绑定的第三方登录账号
	userGroup.DELETE("/delete_third_party_login", DeleteThirdPartyLogin) //删除绑定的第三方登录账号
	//前端用户ui配置
	userGroup.GET("/get_user_ui_config", GetUserUIConfig)  //获取用户ui配置
	userGroup.POST("/set_user_ui_config", SetUserUIConfig) //设置用户ui配置
}

type RLReq struct {
	User     string `json:"username" form:"username"`
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
	Age      int    `json:"age" form:"age"`
	Code     string `json:"code" form:"code"` //验证码
	Gender   string `json:"gender" form:"gender"`
}

type QRReq struct {
	UUID    string `json:"uuid" form:"uuid"`
	Address string `json:"address" form:"address"`
	IP      string `json:"ip" form:"ip"`
}

type SearchReq struct {
	Keyword string `json:"keyword" form:"keyword"`
	ID      int    `json:"id" form:"id"`
}
type GetUserInfoReq struct {
	ID int `json:"id" form:"id"`
}

type ResetPasswordReq struct {
	Email       string `json:"email" form:"email"`
	OldPassword string `json:"old_password" form:"old_password"`
	NewPassword string `json:"new_password" form:"new_password"`
	Type        int    `json:"type" form:"type"` //0获取验证码,2为邮箱验证码重置密码，1为旧密码重置密码
	Code        string `json:"code" form:"code"` //验证码
}

func ResetPassword(c *gin.Context) {
	var req_data ResetPasswordReq
	if err := c.ShouldBind(&req_data); err == nil {
		if req_data.Type == 0 {
			//获取验证码
			//查看是否存在该邮箱
			user := dao.FindUserByEmail(req_data.Email)
			if user.ID == 0 {
				c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "邮箱不存在", "data": "2"})
				return
			}
			if worker.IsContainKey("reset_password_" + req_data.Email) {
				c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "验证码已发送，请5分钟后再试", "data": "2"})
				return
			}
			//随机字符串验证码大写
			code := worker.GetRandomString(6)
			worker.SetRedisWithExpire("reset_password_"+req_data.Email, code, time.Minute*5) //设置5分钟过期`
			//发送邮件
			service.SendEmail(req_data.Email, "大学生学业作品AI生成工具开发重置密码", "验证码:"+code+" ,请在5分钟内使用!")
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": "2"})
			return
		} else if req_data.Type == 1 {
			//旧密码重置密码
			if len(req_data.OldPassword) != 32 {
				hasher := md5.New()
				hasher.Write([]byte(req_data.OldPassword))                 // 生成密码的 MD5 散列值
				req_data.OldPassword = hex.EncodeToString(hasher.Sum(nil)) // 生成密码的 MD5 散列值
			}
			if len(req_data.NewPassword) != 32 {
				hasher := md5.New()
				hasher.Write([]byte(req_data.NewPassword))                 // 生成密码的 MD5 散列值
				req_data.NewPassword = hex.EncodeToString(hasher.Sum(nil)) // 生成密码的 MD5 散列值
			}
			user := dao.FindUserByEmail(req_data.Email)
			if user.ID == 0 {
				c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "邮箱不存在", "data": "2"})
				return
			}
			if user.Password != req_data.OldPassword {
				c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "旧密码错误", "data": "2"})
				return
			}
			if user.Password == req_data.NewPassword {
				c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "新旧密码相同", "data": "2"})
				return
			}
			dao.UpdateUserByID(int(user.ID), user.Name, req_data.NewPassword, user.Email)
			var resp proto.ResponseOAuth
			token, err2 := service.CreateTokenAndSave(user)
			if err2 != nil {
				c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "new token error", "data": resp})
				return
			}
			resp.Token = token
			resp.ID = user.ID
			resp.Name = user.Name
			resp.Email = user.Email
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": resp})
		} else if req_data.Type == 2 {
			//邮箱重置密码
			if len(req_data.NewPassword) != 32 {
				hasher := md5.New()
				hasher.Write([]byte(req_data.NewPassword))                 // 生成密码的 MD5 散列值
				req_data.NewPassword = hex.EncodeToString(hasher.Sum(nil)) // 生成密码的 MD5 散列值
			}
			user := dao.FindUserByEmail(req_data.Email)
			if user.ID == 0 {
				c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "邮箱不存在", "data": "2"})
				return
			}
			code := worker.GetRedis("reset_password_" + req_data.Email)
			if code != req_data.Code {
				c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "验证码错误", "data": "2"})
				return
			}
			dao.UpdateUserByID(int(user.ID), user.Name, req_data.NewPassword, user.Email)
			token, err2 := service.CreateTokenAndSave(user)
			if err2 != nil {
				c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "new token error", "data": "2"})
				return
			}
			var resp proto.ResponseOAuth
			resp.Token = token
			resp.ID = user.ID
			resp.Name = user.Name
			resp.Email = user.Email
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": resp})
		} else {
			c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "type error", "data": "2"})
			return
		}

	} else {
		c.JSON(200, gin.H{"code": proto.ParameterError, "message": err, "data": "2"})
		return
	}
}

func GetUserInfo(c *gin.Context) {
	var req_data GetUserInfoReq
	id, _ := c.Get("id")
	user_id := int(id.(float64))
	if err := c.ShouldBind(&req_data); err == nil {
		var user dao.User
		if req_data.ID == user_id {
			user = dao.FindUserByID2(user_id)
			user.Password = "" //不返回密码
		} else {
			//判断当前用户是否有权限查看
			cur_user := dao.FindUserByID2(user_id)
			if cur_user.Role == "admin" {
				user = dao.FindUserByID2(req_data.ID)
				user.Password = "" //不返回密码
			} else {
				c.JSON(200, gin.H{"code": proto.PermissionDenied, "message": "无权查看", "data": "2"})
				return
			}
		}
		c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": user})
	} else {
		c.JSON(200, gin.H{"code": proto.ParameterError, "message": err, "data": "2"})
		return
	}
}

func DeleteUser(c *gin.Context) {
	var req GetUserInfoReq
	id, _ := c.Get("id")
	user_id := int(id.(float64))
	if err := c.ShouldBind(&req); err == nil {
		res := service.DeleteUserService(req.ID, user_id)
		if res != 0 {
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": res})
		} else {
			c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "failed", "data": res})
		}
	} else {
		c.JSON(200, gin.H{"code": proto.ParameterError, "message": err, "data": "2"})
		return
	}
}

func UpdateUserInfo(c *gin.Context) {
	var req_data proto.UpdateUserInfoReq
	id, _ := c.Get("id")
	user_id := int(id.(float64))
	if err := c.ShouldBind(&req_data); err == nil {
		rid, err2 := service.UpdateUser(user_id, req_data)
		if err2 != nil {
			c.JSON(200, gin.H{"code": proto.OperationFailed, "message": "failed", "data": "2"})
			return
		}
		c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": rid})
	} else {
		c.JSON(200, gin.H{"code": proto.ParameterError, "message": err, "data": "2"})
		return
	}

}

func GetScanUUID(c *gin.Context) {
	var ReqData QRReq
	if err := c.ShouldBind(&ReqData); err != nil {
		c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err, "data": "2"})
		return
	}
	data := map[string]interface{}{"status": "0", "address": ReqData.Address, "ip": c.ClientIP()}
	jsonData, err := json.Marshal(data)
	if err != nil {
		c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err, "data": "2"})
		return
	}
	id := uuid.New()
	res := worker.SetRedisWithExpire(id.String(), string(jsonData), time.Minute*30)
	if res {
		var retrievedData map[string]interface{}
		if err2 := json.Unmarshal([]byte(worker.GetRedis(id.String())), &retrievedData); err2 != nil {
			c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err2, "data": "2"})
			return
		}
		c.JSON(200, gin.H{"code": proto.SuccessCode, "message": retrievedData, "data": id.String()})
	} else {
		c.JSON(200, gin.H{"code": proto.RedisSetError, "message": "qr code invalid", "data": "1"})
	}
}

func SetQRStatus(c *gin.Context) {
	var qrsetReq QRReq
	if err := c.ShouldBind(&qrsetReq); err == nil && qrsetReq.UUID != "" {
		if worker.IsContainKey(qrsetReq.UUID) == false {
			c.JSON(200, gin.H{"code": proto.UUIDNotFound, "message": "uuid not found in server", "data": "0"})
			return
		}
		var retrievedData map[string]interface{}
		if err2 := json.Unmarshal([]byte(worker.GetRedis(qrsetReq.UUID)), &retrievedData); err2 != nil {
			c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err2, "data": "2"})
			return
		}
		retrievedData["status"] = "1"
		jsonData, err2 := json.Marshal(retrievedData)
		if err2 != nil {
			c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err2, "data": "2"})
			return
		}
		res := worker.SetRedisWithExpire(qrsetReq.UUID, string(jsonData), time.Minute*30)
		if res {
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": retrievedData})
		} else {
			c.JSON(200, gin.H{"code": proto.RedisSetError, "message": "qr code invalid", "data": "1"})
		}
	} else {
		c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err, "data": "2"})
	}
}

// 确认返回token数据
func ConfirmQRLogin(c *gin.Context) {
	var qrsetReq QRReq
	if err := c.ShouldBind(&qrsetReq); err == nil && qrsetReq.UUID != "" {
		//user_id, _ := c.Get("id")
		user_name, _ := c.Get("username")
		if user_name != "" {
			key := "user_" + user_name.(string)
			token := worker.GetRedis(key)
			if token == "" {
				c.JSON(200, gin.H{"code": proto.RedisGetError, "message": "Token不存在", "data": "20"})
			}
			if worker.IsContainKey(qrsetReq.UUID) == false {
				c.JSON(200, gin.H{"code": proto.UUIDNotFound, "message": "uuid not found in server", "data": "0"})
				return
			}
			var retrievedData map[string]interface{}
			if err2 := json.Unmarshal([]byte(worker.GetRedis(qrsetReq.UUID)), &retrievedData); err2 != nil {
				c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err2, "data": "2"})
				return
			}
			retrievedData["status"] = token
			jsonData, err2 := json.Marshal(retrievedData)
			if err2 != nil {
				c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err2, "data": "2"})
				return
			}
			if worker.SetRedisWithExpire(qrsetReq.UUID, string(jsonData), time.Minute*10) {
				c.JSON(200, gin.H{"code": 0, "message": "success", "data": "0"})
			} else {
				c.JSON(200, gin.H{"code": proto.RedisSetError, "message": "设置Token失败", "data": "8"})
			}
		} else {
			c.JSON(200, gin.H{"code": proto.RedisGetError, "message": "failed", "data": "20"})
		}
	} else {
		c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err, "data": "3"})
	}
}

func GetQRStatus(c *gin.Context) {
	var qrReq QRReq
	if err := c.ShouldBind(&qrReq); err == nil {
		var retrievedData map[string]interface{}
		if err2 := json.Unmarshal([]byte(worker.GetRedis(qrReq.UUID)), &retrievedData); err2 != nil {
			c.JSON(200, gin.H{"code": proto.DeviceRestartFailed, "message": err2, "data": "2"})
			return
		}
		str := retrievedData["status"].(string)
		switch str {
		case "":
			c.JSON(200, gin.H{"code": proto.UUIDNotFound, "message": "uuid not found", "data": "0"}) //空值
		case "0":
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": "0"}) //空值
		case "1":
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": "1"}) //已扫描待确认
		default:
			// 解析 JWT 令牌
			token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
				return proto.SigningKey, nil
			})
			if err != nil {
				c.JSON(200, gin.H{"error": err.Error(), "code": proto.TokenParseError, "message": "error"})
				return
			}
			// 返回令牌
			data := make(map[string]interface{})
			data["id"] = token.Claims.(jwt.MapClaims)["id"]
			data["username"] = token.Claims.(jwt.MapClaims)["username"]
			data["email"] = token.Claims.(jwt.MapClaims)["email"]
			data["token"] = str
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": data}) //确认返回token数据
		}
	} else {
		c.JSON(200, gin.H{"error": err.Error(), "code": proto.DeviceRestartFailed, "message": "error"})
	}
}

func SearchHandler(c *gin.Context) {
	var req_data SearchReq
	if err := c.ShouldBind(&req_data); err == nil {
		if req_data.ID != -1 {
			user := service.GetUserByID(req_data.ID)
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": user})
			return
		} else if req_data.Keyword != "" {
			users := service.GetUserByNameLike(req_data.Keyword)
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": users})
			return
		} else {
			users := service.GetUsersDefault()
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "error", "data": users})
		}
	} else {
		c.JSON(200, gin.H{"error": err.Error(), "code": proto.ParameterError, "message": "error"})
	}
}

func loginHandler(c *gin.Context) {
	var req_data RLReq
	tokenString := ""
	if err := c.ShouldBind(&req_data); err == nil {
		if len(req_data.Password) != 32 {
			hasher := md5.New()
			hasher.Write([]byte(req_data.Password))                 // 生成密码的 MD5 散列值
			req_data.Password = hex.EncodeToString(hasher.Sum(nil)) // 生成密码的 MD5 散列值
		}
		user := service.GetUser(req_data.User, req_data.Password, req_data.Password)
		if user.ID != 0 {
			key := "user_" + user.Name
			redis_token := worker.GetRedis(string(key))
			if redis_token == "" {
				// 生成 JWT 令牌
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"username": user.Name,
					"id":       user.ID,
					"exp":      time.Now().Add(time.Hour * 24).Unix(), // 令牌过期时间, 24小时后过期
				})
				tokenString, err = token.SignedString(proto.SigningKey)
				if err != nil {
					c.JSON(200, gin.H{"error": err.Error(), "code": proto.TokenGenerationError, "message": "error"})
					return
				}

				worker.SetRedisWithExpire("user_"+user.Name, tokenString, time.Hour*24) // 将用户信息存入
				worker.SetRedisWithExpire(tokenString, tokenString, time.Hour*24)       // 设置过期时间为24h
				data := make(map[string]interface{})
				data["id"] = user.ID
				data["username"] = user.Name
				data["email"] = user.Email
				worker.SetHash(tokenString, data) // 将用户信息存入
			} else {
				tokenString = redis_token
			}
			// 返回令牌
			data := make(map[string]interface{})
			data["id"] = user.ID
			data["username"] = user.Name
			data["email"] = user.Email
			data["token"] = tokenString
			c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": data})
		} else {
			//用户名或密码错误
			c.JSON(200, gin.H{"error": "用户名或密码错误", "code": proto.UsernameOrPasswordError, "message": "error"})
		}
	} else {
		c.JSON(200, gin.H{"error": err.Error(), "code": proto.DeviceRestartFailed, "message": "error"})
	}
}

func registerHandler(c *gin.Context) {
	var req_data RLReq
	tokenString := ""
	var id uint
	if err := c.ShouldBind(&req_data); err == nil {
		if len(req_data.Password) != 32 {
			hasher := md5.New()
			hasher.Write([]byte(req_data.Password))                 // 生成密码的 MD5 散列值
			req_data.Password = hex.EncodeToString(hasher.Sum(nil)) // 生成密码的 MD5 散列值
		}
		if service.ContainsUser(req_data.User, req_data.Email) == true {
			c.JSON(200, gin.H{"error": "user already exists", "code": proto.UsernameExists, "message": "error"})
			return
		}
		id = service.CreateUser(req_data.User, req_data.Password, req_data.Email, req_data.Gender, req_data.Age)
		if id == 0 {
			c.JSON(200, gin.H{"error": "create user error", "code": proto.OperationFailed, "message": "error"})
			return
		}
		// 生成 JWT 令牌
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": req_data.User,
			"id":       id,
			"exp":      time.Now().Add(time.Hour * 24).Unix(), // 令牌过期时间, 1分钟后过期
		})
		tokenString, err = token.SignedString(proto.SigningKey)
		if err != nil {
			c.JSON(200, gin.H{"error": err.Error(), "code": proto.TokenGenerationError, "message": "error"})
			return
		}
	} else {
		c.JSON(200, gin.H{"error": err.Error(), "code": proto.ParameterError, "message": "error"})
		return
	}
	fmt.Println(req_data)
	res := worker.SetRedisWithExpire(tokenString, tokenString, time.Hour*24) // 设置过期时间为24h
	if !res {
		c.JSON(200, gin.H{"error": "set token error", "code": proto.RedisSetError, "message": "error"})
		return
	}
	// 返回令牌
	data := make(map[string]interface{})
	data["id"] = id
	data["username"] = req_data.User
	data["email"] = req_data.Email
	data["token"] = tokenString
	c.JSON(200, gin.H{"code": proto.SuccessCode, "message": "success", "data": data})
	return
}

func registerHandlerV2(c *gin.Context) {
	var reqData RLReq
	var resp proto.GenerateResp
	if err := c.ShouldBind(&reqData); err == nil {
		if reqData.User == "" || reqData.Email == "" || reqData.Password == "" {
			resp.Code = proto.ParameterError
			resp.Message = "必要参数不能为空"
		} else {
			//校验验证码
			code := worker.GetRedis("register_code_" + reqData.Email)
			if code != reqData.Code {
				resp.Code = proto.OperationFailed
				resp.Message = "验证码错误"
			} else {
				if len(reqData.Password) != 32 {
					hasher := md5.New()
					hasher.Write([]byte(reqData.Password))                 // 生成密码的 MD5 散列值
					reqData.Password = hex.EncodeToString(hasher.Sum(nil)) // 生成密码的 MD5 散列值
				}
				if service.ContainsUser(reqData.User, reqData.Email) == true {
					resp.Code = proto.UsernameExists
					resp.Message = "用户名或邮箱已存在"
				} else {
					id := service.CreateUser(reqData.User, reqData.Password, reqData.Email, reqData.Gender, reqData.Age)
					if id == 0 {
						resp.Code = proto.OperationFailed
						resp.Message = "创建用户失败"
					} else {
						// 生成 JWT 令牌
						token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
							"username": reqData.User,
							"id":       id,
							"exp":      time.Now().Add(time.Hour * 24).Unix(), // 令牌过期时间, 24小时后过期
						})
						tokenString, err2 := token.SignedString(proto.SigningKey)
						if err2 != nil {
							resp.Code = proto.TokenGenerationError
							resp.Message = "生成token失败"
						} else {
							// 返回令牌
							data := make(map[string]interface{})
							data["id"] = id
							data["username"] = reqData.User
							data["email"] = reqData.Email
							data["token"] = tokenString
							resp.Code = proto.SuccessCode
							resp.Message = "success"
							resp.Data = data
						}
					}
				}
			}
		}
	} else {
		resp.Code = proto.ParameterError
		resp.Message = "解析参数失败"
	}
	c.JSON(http.StatusOK, resp)
}

func LoginOAuth(c *gin.Context) {
	uuid := c.Query("uuid")
	var resp proto.GenerateResp
	if uuid == "" {
		resp.Code = proto.ParameterError
		resp.Message = "uuid is empty"
		c.JSON(200, resp)
		return
	}
	//获取用户信息
	loginStatus := worker.GetRedis(uuid)
	if loginStatus == "" {
		resp.Code = proto.ThirdPartyLoginUUIDInvalid
		resp.Message = "已失效"
		c.JSON(200, resp)
		return
	}
	var status proto.ThirdPartyLoginStatus
	if err := json.Unmarshal([]byte(loginStatus), &status); err != nil {
		resp.Code = proto.OperationFailed
		resp.Message = "error"
		c.JSON(200, resp)
		return
	}
	if status.Status == 0 {
		worker.DelRedis(uuid) //删除uuid,只能查一次
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = status
	c.JSON(200, resp)
}

func GetOAuthUUID(c *gin.Context) {
	var resp proto.GenerateResp
	loginType := c.Query("type")
	if loginType == "" {
		resp.Code = proto.ParameterError
		resp.Message = "type is empty"
		c.JSON(200, resp)
		return
	}
	uuid := uuid.NewString()
	//设置状态
	var status proto.ThirdPartyLoginStatus
	status.Status = 1
	status.Type = loginType
	//设置过期时间
	statusStr, _ := json.Marshal(status)
	worker.SetRedisWithExpire(uuid, string(statusStr), time.Minute*10) //10min过期
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = uuid
	c.JSON(200, resp)
}

func GetThirdPartyLoginList(c *gin.Context) {
	var resp proto.GenerateResp
	//获取用户信息
	id, _ := c.Get("id")
	userId := int(id.(float64))
	thirdPartyLoginList := dao.FindThirdPartyUserInfoByUserID(userId)
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = thirdPartyLoginList
	c.JSON(200, resp)
}

func DeleteThirdPartyLogin(c *gin.Context) {
	var resp proto.GenerateResp
	//获取用户信息
	id, _ := c.Get("id")
	userId := int(id.(float64))
	var req proto.DeleteThirdPartyLoginReq
	if err := c.ShouldBind(&req); err == nil {
		err2 := dao.DeleteThirdPartyLoginByID(req.ID, userId)
		if err2 != nil {
			resp.Code = proto.OperationFailed
			resp.Message = "删除失败！请检查是否属于或者已被删除"
		} else {
			resp.Code = proto.SuccessCode
			resp.Message = "success"
		}
	} else {
		resp.Code = proto.ParameterError
		resp.Message = "error"
	}
	c.JSON(200, resp)
}

func handleRegisterCode(c *gin.Context) {
	var resp proto.GenerateResp
	var req RLReq
	if err := c.ShouldBind(&req); err == nil {
		if req.Email == "" {
			resp.Code = proto.ParameterError
			resp.Message = "email is empty"
		} else {
			//查看是否存在该邮箱
			user := dao.FindUserByEmail(req.Email)
			if user.ID != 0 {
				resp.Code = proto.OperationFailed
				resp.Message = "邮箱已存在，请更换邮箱"
			} else {
				//随机字符串验证码大写
				code := worker.GetRandomString(6)
				worker.SetRedisWithExpire("register_code_"+req.Email, code, time.Minute*5) //设置5分钟过期
				//发送邮件
				service.SendEmail(req.Email, "大学生学业作品AI生成工具开发注册邮件验证码", "验证码:"+code+" ,请在5分钟内使用!")
				resp.Code = proto.SuccessCode
				resp.Message = "success"
			}
		}
	} else {
		resp.Code = proto.ParameterError
		resp.Message = err.Error()
	}
	c.JSON(http.StatusOK, resp)
}

func GetUserUIConfig(c *gin.Context) {
	id, _ := c.Get("user_id")
	userId := id.(int)
	var resp proto.GenerateResp
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = service.GetUserUIConfigInfo(userId)
	c.JSON(http.StatusOK, resp)
}

func SetUserUIConfig(c *gin.Context) {
	id, _ := c.Get("user_id")
	userId := id.(int)
	var req proto.UserUIConfigInfo
	var resp proto.GenerateResp
	if err := c.ShouldBind(&req); err == nil {
		err2 := service.SetUserUIConfigInfo(userId, req)
		if err2 != nil {
			resp.Code = proto.OperationFailed
			resp.Message = "设置失败！请检查是否属于或者已被删除"
		} else {
			resp.Code = proto.SuccessCode
			resp.Message = "success"
		}
	} else {
		resp.Code = proto.ParameterError
		resp.Message = "error:" + err.Error()
	}
	c.JSON(http.StatusOK, resp)
}
