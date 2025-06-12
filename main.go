package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/robfig/cron/v3"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"user_center/dao"
	"user_center/handler"
	"user_center/proto"
	"user_center/service"
	"user_center/worker"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	err := dao.Init()
	if err != nil {
		panic("failed to connect database:" + err.Error())
	}
	err = dao.InitMongoDB()
	if err != nil {
		panic("failed to connect mongodb:" + err.Error())
	}
	err = worker.InitRedis()
	if err != nil {
		panic("failed to connect redis:" + err.Error())
	}
	r.Use(handler.CrosHandler())
	r.Use(JWTAuthMiddleware()) // 使用 JWT 认证中间件
	handler.SetUpUserGroup(r)  // User
	handler.SetUpToolGroup(r)  // Tool
	defer dao.Close()
	defer worker.CloseRedis()
	defer dao.CloseMongoDB()
	//定时任务
	c := cron.New(cron.WithSeconds())
	// 添加每 10 秒执行一次的任务
	_, err = c.AddFunc("@every 10s", myTask)
	if err != nil {
		log.Fatal("添加定时任务失败: ", err)
	}
	c.Start()
	//读取配置文件，设置系统
	ReadConfigToSetSystem()
	r.Run(":" + proto.Config.SERVER_PORT) // listen and serve on 0.0.0.0:8083
}
func init() {
	// 创建cid的目录
	os.MkdirAll(proto.CID_BASE_DIR, os.ModePerm)
	os.MkdirAll(proto.CID_BASE_DIR+"script", os.ModePerm)
	os.MkdirAll(proto.CID_BASE_DIR+"workspace", os.ModePerm)
	//系统是linux、macos还是windows
	var configPath string
	if os.Getenv("OS") == "Windows_NT" {
		configPath = "E:/Code/user_center.conf"
	} else if os.Getenv("OS") == "linux" {
		//文件地址/home/saw-ai/saw-ai.conf
		configPath = "/home/saw/user_center.conf"
	} else {
		configPath = "/home/saw/user_center.conf"
	}
	//读取配置文件
	err := proto.ReadConfig(configPath)
	if err != nil {
		panic("failed to read config file:" + err.Error())
	}
}

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头中获取 JWT 令牌
		tokenString := c.Request.Header.Get("Authorization")
		if tokenString != "" {
			// 如果 tokenString 以 Bearer 开头，则去掉前缀
			if strings.HasPrefix(tokenString, "Bearer ") {
				tokenString = strings.TrimPrefix(tokenString, "Bearer ")
			}
		} else {
			tokenString = c.Request.Header.Get("token")
			if tokenString == "" {
				tokenString = c.Query("token") // 从查询参数中获取 token
			}
		}
		//请求方式为get时，从url中获取token
		if tokenString == "" {
			tokenString = c.Query("token")
		}
		//for k, _ := range proto.Url_map {
		//	if strings.Contains(c.Request.URL.Path, k) {
		//		log.Println("need not check token:", c.Request.URL.Path)
		//		c.Next()
		//		return
		//	}
		//}
		if proto.Url_map[c.Request.URL.Path] == true { //查看是否在不需要token的url中
			c.Next()
			return
		}
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{"message": "unauthorized", "error": "token is empty", "code": proto.TokenIsNull})
			return
		}
		if proto.Config.TOKEN_USE_REDIS {
			redisToken := worker.GetRedis(tokenString)
			if redisToken == "" {
				c.AbortWithStatusJSON(http.StatusOK, gin.H{"message": "NOT_LOGIN", "error": "server token is empty", "code": proto.TokenIsNull})
				return
			}
		}
		//查看token是否在超级token中
		if worker.IsContainSet("super_permission_tokens", tokenString) {
			sId := c.Request.Header.Get("super_id")
			if sId == "" {
				sId = c.Query("super_id")
			}
			if sId == "" {
				c.AbortWithStatusJSON(http.StatusOK, gin.H{"message": "unauthorized", "error": "super_id is empty", "code": proto.TokenIsNull})
				return
			}
			id, _ := strconv.Atoi(sId)
			idFloat64 := float64(id)
			//查看s_id类型
			c.Set("id", idFloat64)
			c.Set("user_id", id)
			c.Next()
			return
		}

		// 使用加密secret 解析 JWT 令牌
		//token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//	return proto.SigningKey, nil
		//})
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			// 验证签名算法
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return proto.SigningKey, nil
		})
		// 错误处理
		if err != nil {
			var ve *jwt.ValidationError
			if errors.As(err, &ve) {
				switch {
				case ve.Errors&jwt.ValidationErrorMalformed != 0:
					c.AbortWithStatusJSON(http.StatusOK, gin.H{"error": "Malformed token:" + err.Error() + ",token is: " + tokenString, "code": proto.TokenInvalid})
				case ve.Errors&jwt.ValidationErrorExpired != 0:
					c.AbortWithStatusJSON(http.StatusOK, gin.H{"error": "Token expired:" + err.Error() + ",token is: " + tokenString, "code": proto.TokenExpired})
				case ve.Errors&jwt.ValidationErrorNotValidYet != 0:
					c.AbortWithStatusJSON(http.StatusOK, gin.H{"error": "Token not active yet:" + err.Error() + ",token is: " + tokenString, "code": proto.TokenInvalid})
				default:
					c.AbortWithStatusJSON(http.StatusOK, gin.H{"error": "Invalid token:" + err.Error() + ",token is: " + tokenString, "code": proto.TokenInvalid})
				}
				return
			}
		}

		// 将用户信息添加到上下文中
		id := token.Claims.(jwt.MapClaims)["id"]
		tokenType := token.Claims.(jwt.MapClaims)["type"]
		c.Set("id", id)
		c.Set("user_id", int(id.(float64)))
		c.Set("tokenType", tokenType.(string)) // 添加 token 类型到上下文中

		if UserFuncIntercept(int(id.(float64)), c.Request.URL.Path) {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{"message": "unauthorized", "error": "no function permission", "code": proto.NoPermission})
			return
		}
		// 继续处理请求
		c.Next()
		//log.Println("JWT token is valid, user ID:", token.Claims.(jwt.MapClaims)["id"], " path:", c.Request.URL.Path)
	}
}

func myTask() {
	// 定时任务
	//redis中取出数据
	//handler.RunCron()
	if proto.Config.MONITOR {
		handler.ScanDeviceStatus()
	}
	//其它定时任务-通用
	RunGeneralCron()
}

func ReadConfigToSetSystem() {
	//将当前配置文件的信息写入redis,用于程序运行时排查
	config_json, c_err := json.Marshal(proto.Config)
	if c_err != nil {
		fmt.Println("ReadConfigToSetSystem Error encoding config,err :", c_err)
	} else {
		worker.SetRedis("system_config_info", string(config_json))
	}

	//redis添加通用定时任务
	key := "cron_info"
	//日志清理
	res := worker.GetRedis(key)
	var cron_infos []proto.CronInfo
	if res != "" {
		err := json.Unmarshal([]byte(res), &cron_infos)
		if err != nil {
			fmt.Println("ReadConfigToSetSystem Error decoding config,key value is :", res)
		}

		//查看清除日志任务是否存在
		if proto.Config.LOG_SAVE_DAYS > 0 {
			var is_exist bool
			for _, v := range cron_infos {
				if v.Type == 1 {
					is_exist = true
					break
				}
			}
			if !is_exist {
				var logClean proto.CronInfo
				logClean.Type = 1
				logClean.Info = "日志清理"
				logClean.Curr = 86400
				logClean.Every = 86400
				cron_infos = append(cron_infos, logClean)
			}
		}

		is_exist := false
		user_sync_id := -1 //用户同步任务索引
		for i, v := range cron_infos {
			if v.Type == 2 {
				is_exist = true
				if proto.Config.USER_SYNC_TIME != v.Every {
					v.Every = proto.Config.USER_SYNC_TIME
					v.Curr = proto.Config.USER_SYNC_TIME
				}
				user_sync_id = i
				cron_infos[i] = v
				break
			}
		}
		if proto.Config.SERVER_USER_TYPE == "slave" {
			if proto.Config.USER_SYNC_TIME > 0 && !is_exist {
				var userSync proto.CronInfo
				userSync.Type = 2
				userSync.Info = "user"
				userSync.Curr = proto.Config.USER_SYNC_TIME
				userSync.Every = proto.Config.USER_SYNC_TIME
				cron_infos = append(cron_infos, userSync)
			} else if user_sync_id != -1 {
				cron_infos = append(cron_infos[:user_sync_id], cron_infos[user_sync_id+1:]...) //删除
			}
		}

	} else {
		if proto.Config.LOG_SAVE_DAYS > 0 {
			var logClean proto.CronInfo
			logClean.Type = 1
			logClean.Info = "日志清理"
			logClean.Curr = 86400
			logClean.Every = 86400
			cron_infos = append(cron_infos, logClean)
		}
		if proto.Config.SERVER_USER_TYPE == "slave" && proto.Config.USER_SYNC_TIME > 0 {
			var userSync proto.CronInfo
			userSync.Type = 2
			userSync.Info = "user"
			userSync.Curr = proto.Config.USER_SYNC_TIME
			userSync.Every = proto.Config.USER_SYNC_TIME
			cron_infos = append(cron_infos, userSync)
		}
	}
	//存入redis
	json_data, err := json.Marshal(cron_infos)
	if err != nil {
		fmt.Println("ReadConfigToSetSystem Error encoding config,value is :", cron_infos)
	} else {
		worker.SetRedis(key, string(json_data))
	}
}

func RunGeneralCron() {
	//redis添加通用定时任务
	key := "cron_info"
	//日志清理
	res := worker.GetRedis(key)
	var cron_infos []proto.CronInfo
	if res != "" {
		err := json.Unmarshal([]byte(res), &cron_infos)
		if err != nil {
			fmt.Println("RunGeneralCron Error decoding config,key value is :", res)
		}
		//存入redis
		json_data, err := json.Marshal(cron_infos)
		if err != nil {
			fmt.Println("RunGeneralCron Error encoding config,value is :", cron_infos)
		} else {
			worker.SetRedis(key, string(json_data))
		}
	}
}

// 用户功能拦截,返回true表示拦截，false表示不拦截
func UserFuncIntercept(id int, url string) bool {
	//先查看是否有权限
	user := service.GetUserByIDWithCache(id)
	//如果用户有权限，则不拦截
	for k, v := range proto.Per_menu_map {
		if strings.Contains(url, k) {
			if v == 1 && user.VideoFunc == false {
				return true
			}
			if v == 2 && user.DeviceFunc == false {
				return true
			}
			if v == 3 && user.CIDFunc == false {
				return true
			}
		}
	}
	return false
}
