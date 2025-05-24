package proto

import (
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
	"log"
	"os"
)

var Config ConfigStruct
var SigningKey = []byte{}
var Url_map = map[string]bool{"/login": true, "/register": true, "/uuid": true, "/gqr": true, "/cid/callback": true, "/tool/monitor": true, "/user/sync": true, "/tool/file/": true, "/user/reset": true, "/tool/qq_auth": true, "/tool/qq_callback": true, "/tool/github_auth": true, "/tool/github_callback": true, "/user/oAuth": true, "/user/oAuth_uuid": true, "/tool/loginRedirect": true, "/tool/get_auth_url": true, "/tool/gitee_callback": true, "/tool/third_party_callback": true, "/user/refresh_token": true} // 不需要token验证的url
var Per_menu_map = map[string]int{"/video/": 1, "/device/": 2, "/cid/": 3}
var File_Type = map[string]int{"im": 1, "avatar": 2, "file": 3, "config": 4} // 文件类型
const (
	MYSQL_USER     = "video_t2"
	MYSQL_DB       = "video_t2"
	MYSQL_PASSWORD = "2t2SKHmWEYj2xFKF"
	MYSQL_PORT     = "3306"
	MYSQL_HOST     = "127.0.0.1"
	MYSQL_DSN      = MYSQL_USER + ":" + MYSQL_PASSWORD + "@tcp(" + MYSQL_HOST + ":" + MYSQL_PORT + ")/" + MYSQL_DB + "?charset=utf8mb4&parseTime=True&loc=Local"

	REDIS_ADDR     = "127.0.0.1:6379"
	REDIS_PASSWORD = "lj502138"
	REIDS_DB       = 2

	TOKEN_SECRET = "mfjurnc_32ndj9dfhj"

	// 以下是持续集成、部署的配置
	CID_BASE_DIR = "/home/lijun/cid/"

	// 以下是文件上传的配置
	FILE_BASE_DIR = "/home/lijun/file/"
)

const (
	// 以下是消息类型
	MSG_TYPE_SIMPLE     = 1 // 单聊
	MSG_TYPE_GROUP      = 2 // 群聊
	MSG_TYPE_SYSTEM     = 3 // 系统消息
	MSG_TYPE_FRIEND     = 4 // 好友请求
	MSG_TYPE_GROUP_ADD  = 5 // 加入群聊请求
	MSG_TYPE_GROUP_INVI = 6 // 邀请加入群聊

	// 以下是消息状态
	MSG_STATUS_READ   = 1 // 已读
	MSG_STATUS_UNREAD = 0 // 未读
)

const (
	//文件上传类型
	File_TYPE = 1 // 通用文件
	//用于视频解析
	Video_TYPE = 2 // 视频文件
)

type User struct {
	gorm.Model
	Name   string `gorm:"column:name"`
	Age    int    `gorm:"column:age"`
	Email  string `gorm:"column:email"`
	Gender string `gorm:"column:gender"`
	Role   string `gorm:"column:role"`
}

type ConfigStruct struct {
	DB                        int           `json:"db"` // 0: mysql, 1: pg
	MYSQL_DSN                 string        `json:"mysql_dsn"`
	PG_DSN                    string        `json:"pg_dsn"`
	MONGO_URI                 string        `json:"mongo_uri"`
	MONGO_DATABASE            string        `json:"mongo_database"`
	SlowQueryThreshold        int           `json:"slow_query_threshold"` // 慢查询阈值，单位ms
	REDIS_ADDR                string        `json:"redis_addr"`
	TOKEN_USE_REDIS           bool          `json:"token_use_redis"`
	REDIS_User_PW             bool          `json:"redis_user_pw"` // 是否使用密码
	REDIS_PASSWORD            string        `json:"redis_password"`
	REDIS_DB                  int           `json:"redis_db"`
	TOKEN_SECRET              string        `json:"token_secret"`
	CID_BASE_DIR              string        `json:"cid_base_dir"`
	FILE_BASE_DIR             string        `json:"file_base_dir"`
	LOG_OUTPUT                bool          `json:"log_output"`
	AISessionNameModelID      int           `json:"ai_session_name_model_id"`    // 用于ai总结会话名称的模型id
	MONITOR                   bool          `json:"monitor"`                     // 状态监控及邮件通知
	SERVER_SQL_LOG            bool          `json:"server_sql_log"`              // 服务器sql日志
	SERVER_PORT               string        `json:"server_port"`                 // 服务端口
	LOG_SAVE_DAYS             int           `json:"log_save_days"`               // 日志保存天数,-1表示不保存，0表示永久保存
	SERVER_USER_TYPE          string        `json:"user_type"`                   // 服务器用户类型，master: 主服务器，slave: 从服务器，从服务器会定时同步数据
	MASTER_SERVER_DOMAIN      string        `json:"master_server_domain"`        // 主服务器域名
	USER_SYNC_TIME            int           `json:"user_sync_time"`              // 用户数据同步时间，单位秒
	SERVER_NAME               string        `json:"server_name"`                 // 服务器名称,用于区分不同服务器
	SPARK_PPT_USAGE           bool          `json:"spark_ppt_usage"`             // 是否使用spark ppt功能
	KBASE_SERVER              []KBaseServer `json:"kbase_server"`                // 知识库服务器列表
	GITHUB_CLIENT_ID          string        `json:"github_client_id"`            // github client id
	GITHUB_CLIENT_SECRET      string        `json:"github_client_secret"`        // github client secret
	GITEE_CLIENT_ID           string        `json:"gitee_client_id"`             // gitee client id
	GITEE_CLIENT_SECRET       string        `json:"gitee_client_secret"`         // gitee client secret
	MICROSOFT_CLIENT_SECRET   string        `json:"microsoft_client_secret"`     // microsoft client secret
	GITEA_CLIENT_SECRET       string        `json:"gitea_client_secret"`         // gitea client secret
	MyGiteaClientSecret       string        `json:"my_gitea_client_secret"`      // my gitea client secret
	QQClientSecret            string        `json:"qq_client_secret"`            // qq client secret
	StackOverflowClientSecret string        `json:"stackoverflow_client_secret"` // stack overflow client secret
	FacebookClientSecret      string        `json:"facebook_client_secret"`      // facebook client secret
	GoogleClientSecret        string        `json:"google_client_secret"`        // google client secret
}

type KBaseServer struct {
	ServerID string `json:"server_id"` // 服务器ID
}

// 读取配置文件
func ReadConfig(path string) error {
	//查看配置文件是否存在,不存在则创建
	_, err := os.Stat(path)
	if err != nil {
		fmt.Println("Config file not found!")
		//创建默认配置
		DefaultConfig()
		//写入json文件
		file, err := os.Create(path)
		if err != nil {
			fmt.Println("Error creating config file")
			return err
		}
		defer file.Close()
		encoder := json.NewEncoder(file)
		err = encoder.Encode(&Config)
		if err != nil {
			fmt.Println("Error encoding config")
		}
		return err
	}

	//读json文件
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Error opening config file")
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&Config)
	if err != nil {
		fmt.Println("Error decoding config")
	} else {
		if Config.SERVER_PORT == "" {
			Config.SERVER_PORT = "8083" // 默认端口
		}
	}
	SigningKey = []byte(Config.TOKEN_SECRET)
	//将当前配置文件的信息写入redis,用于程序运行时排查
	configJson, cErr := json.Marshal(Config)
	if cErr != nil {
		log.Println("ReadConfig Error encoding config,err :", cErr)
	} else {
		log.Println("ReadConfig configJson:", string(configJson))
	}
	return err
}

// 默认配置
func DefaultConfig() {
	Config.DB = 2
	Config.MYSQL_DSN = MYSQL_DSN
	Config.PG_DSN = ""
	Config.SlowQueryThreshold = 400
	Config.REDIS_ADDR = REDIS_ADDR
	Config.TOKEN_USE_REDIS = false
	Config.REDIS_User_PW = false
	Config.REDIS_PASSWORD = REDIS_PASSWORD
	Config.REDIS_DB = REIDS_DB
	Config.TOKEN_SECRET = TOKEN_SECRET
	Config.CID_BASE_DIR = CID_BASE_DIR
	Config.FILE_BASE_DIR = FILE_BASE_DIR
	Config.MONITOR = false
	Config.SERVER_SQL_LOG = false
	Config.SERVER_PORT = "8085"
	Config.LOG_SAVE_DAYS = 7
	Config.SERVER_USER_TYPE = "master"
	Config.MASTER_SERVER_DOMAIN = ""
	Config.USER_SYNC_TIME = 86400
	Config.SERVER_NAME = "default"
	Config.SPARK_PPT_USAGE = false
}
