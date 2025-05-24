package proto

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

// Token expiration durations
const (
	AccessTokenDuration  = time.Hour
	RefreshTokenDuration = 7 * 24 * time.Hour
)

type GenerateResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

type ResponseOAuth struct {
	ID    uint   `json:"id" form:"id"`
	Name  string `json:"name" form:"name"`
	Email string `json:"email" form:"email"`
	Token string `json:"token" form:"token"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       uint   `json:"user_id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
}

type UpdateUserInfoReq struct {
	ID         int    `json:"id" form:"id"`                   //用户id
	Username   string `json:"name" form:"name"`               //用户名
	Age        int    `json:"age" form:"age"`                 //年龄
	Role       string `json:"role" form:"role"`               //角色
	Gender     string `json:"gender" form:"gender"`           //性别
	Redis      bool   `json:"redis" form:"redis"`             //是否刷新redis
	Upload     bool   `json:"upload" form:"upload"`           //是否上传头像
	VideoFunc  bool   `json:"video_func" form:"video_func"`   //视频功能
	DeviceFunc bool   `json:"device_func" form:"device_func"` //设备功能
	CIDFunc    bool   `json:"cid_func" form:"cid_func"`       //持续集成功能
	Run        bool   `json:"run" form:"run"`                 //是否运行
	QQ         int64  `json:"qq" form:"qq"`                   //QQ
	Avatar     string `json:"avatar" form:"avatar"`           //头像
}

type UserAddOrUpdate struct {
	ID         uint      `json:"ID" form:"ID"`               //用户id
	CreatedAt  time.Time `json:"CreatedAt" form:"CreatedAt"` //创建时间
	UpdatedAt  time.Time `json:"UpdatedAt" form:"UpdatedAt"` //更新时间
	DeletedAt  time.Time `json:"DeletedAt" form:"DeletedAt"` //删除时间
	Name       string    `json:"Name" form:"Name"`           //用户名
	Age        int       `json:"Age" form:"Age"`             //年龄
	Email      string    `json:"Email" form:"Email"`         //邮箱
	Password   string    `json:"Password" form:"Password"`   //密码
	Gender     string    `json:"Gender" form:"Gender"`       //性别
	Role       string    `json:"Role" form:"Role"`           //角色
	Redis      bool      `json:"Redis" form:"Redis"`         //是否刷新redis
	Run        bool      `json:"Run" form:"Run"`             //是否运行
	Upload     bool      `json:"Upload" form:"Upload"`       //是否上传头像
	VideoFunc  bool      `json:"VideoFunc" form:"VideoFunc"` //视频功能
	DeviceFunc bool      `json:"DeviceFunc" form:"DeviceFunc"`
	CIDFunc    bool      `json:"CIDFunc" form:"CIDFunc"`
	Avatar     string    `json:"Avatar" form:"Avatar"` //头像
	CreateTime string    `json:"CreateTime" form:"CreateTime"`
	UpdateTime string    `json:"UpdateTime" form:"UpdateTime"`
}

type UserDelID struct {
	ID uint `json:"ID" form:"ID"` //用户id
}

// 第三方登录,登录状态
type ThirdPartyLoginStatus struct {
	Status   int          `json:"status"`    // 登录状态,0:登录成功,1:登录失败
	Type     string       `json:"type"`      // 登录类型,qq,github
	UserInfo AuthResponse `json:"user_info"` // 用户信息
}

type UserLoginInfo struct {
	UserID   int    `json:"id"`       // 用户ID
	Username string `json:"username"` // 用户名
	Email    string `json:"email"`    // 用户邮箱
	Token    string `json:"token"`    // 用户token
}

// 第三方登录state
type ThirdPartyLoginState struct {
	UUID    string `json:"uuid"`    // uuid
	Type    string `json:"type"`    // 操作类型add,login
	Project string `json:"project"` // 项目名称,saw
	//第三方平台
	Platform string `json:"platform"` // 平台名称,qq,github
	UserID   int    `json:"user_id"`  // 用户ID,当为add时需要
}

// 国外服务器负责请求的请求
type OnlineServerReq struct {
	Type     string                 `json:"type" form:"type"`           // 请求类型,get,post
	PostType string                 `json:"post_type" form:"post_type"` // post请求类型,form,json
	Url      string                 `json:"url" form:"url"`             // 请求地址
	Data     any                    `json:"data" form:"data"`           // 请求数据
	Header   []OutlineServerReqData `json:"header" form:"header"`       // 请求头
}
type OutlineServerReqData struct {
	Key   string `json:"key" form:"key"`     // 请求的key
	Value string `json:"value" form:"value"` // 请求的值
}

type DeleteThirdPartyLoginReq struct {
	ID int `json:"id" form:"id"` //用户第三方登录信息表ID
}

// 用户对前端交互的配置信息结构,mongodb
type UserUIConfigInfo struct {
	ID            primitive.ObjectID       `bson:"_id,omitempty"`                                                 // 自动生成ID
	UserID        int                      `json:"user_id" form:"user_id" bson:"user_id"`                         // 用户ID
	Theme         string                   `json:"theme" form:"theme" bson:"theme"`                               // 主题
	Language      string                   `json:"language" form:"language" bson:"language"`                      // 语言
	FontSize      int                      `json:"font_size" form:"font_size" bson:"font_size"`                   // 字体大小
	GenAIFunction UserUIFunctionConfigInfo `json:"gen_ai_function" form:"gen_ai_function" bson:"gen_ai_function"` // 生成AI功能配置
	KBaseFunction UserUIFunctionConfigInfo `json:"k_base_function" form:"k_base_function" bson:"k_base_function"` // 知识库功能配置
}

type UserUIFunctionConfigInfo struct {
	ModelID     int     `json:"model_id" form:"model_id" bson:"model_id"`          // 模型ID,选择的模型
	SessionID   int     `json:"session_id" form:"session_id" bson:"session_id"`    // 会话ID,上一次的会话
	Temperature float32 `json:"temperature" form:"temperature" bson:"temperature"` // 温度
	TopP        float32 `json:"top_p" form:"top_p" bson:"top_p"`                   // 采样温度
}

// 用于执行函数，方法
type CronInfo struct {
	Type  int    `json:"type" form:"type"`   //类型编码,1日志清理（且只会有一个），其他待定，2从服务器同步数据
	Info  string `json:"info" form:"info"`   //信息
	Curr  int    `json:"curr" form:"curr"`   //当前剩余时间，每次执行减10s小于等于0则执行
	Every int    `json:"every" form:"every"` //每隔多少秒执行一次,小于等于0表示不执行，时间粒度为10s
}

// github
type GitHubOAuthResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type GiteeOAuthTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	CreatedAt        int    `json:"created_at"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type GoogleOAuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"` // id_token
}

type GoogleOAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"` // authorization_code
}

type OAuthGetTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri" `
}

type GitHubOAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

type GiteeOAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri" `
	//'grant_type': 'authorization_code',
	GrantType string `json:"grant_type"`
}

type ThirdPartyUserInfo struct {
	UserID string `json:"user_id"` // 第三方用户ID
	Email  string `json:"email"`   // 第三方平台用户邮箱
	Avatar string `json:"avatar"`  // 第三方平台用户头像
	Name   string `json:"name"`    // 第三方平台用户名
	Url    string `json:"url"`     // 第三方平台用户主页,可选
	// 其他信息
}

// github返回用户信息
type GitHubUserInfo struct {
	LoginUserName string `json:"login"`      // 用户名
	UserID        int    `json:"id"`         // 用户ID
	AvatarUrl     string `json:"avatar_url"` //头像
	Url           string `json:"url"`        // 用户主页
}

type GoogleUserInfoResp struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

type OnlineServerRespData struct {
	Response string `json:"response"` // 响应数据
}

type OutlineServerResp struct {
	Request  OnlineServerReq      `json:"request" form:"request"`   // 请求
	Response OnlineServerRespData `json:"response" form:"response"` // 响应
}

type OutlineServerReqResp struct {
	Code    int               `json:"code"`    // 响应码
	Message string            `json:"message"` // 响应信息
	Data    OutlineServerResp `json:"data"`    // 响应数据
}

// google回调信息
type GoogleOAuthCallback struct {
	Code        string `json:"code"`         // code
	AccessToken string `json:"access_token"` // access_token
	Scope       string `json:"scope"`        // scope
	State       string `json:"state"`        // state
}

/**************************facebook****************************/
type FacebookOAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type FaceBookOAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

type FaceBookUserInfoResp struct {
	ID      string                  `json:"id"`
	Name    string                  `json:"name"`
	Picture FaceBookUserInfoPicture `json:"picture"`
}

type FaceBookUserInfoPicture struct {
	Data FaceBookUserInfoPictureData `json:"data"`
}

type FaceBookUserInfoPictureData struct {
	Height       int    `json:"height"`
	Width        int    `json:"width"`
	IsSilhouette bool   `json:"is_silhouette"`
	Url          string `json:"url"`
}

/***************************Stackoverflow****************************/
type StackoverflowOAuthResponse struct {
	AccessToken string `json:"access_token"`
	Expires     int    `json:"expires"`
}

type StackoverflowUserInfoBadgeCounts struct {
	Bronze int `json:"bronze"`
	Silver int `json:"silver"`
	Gold   int `json:"gold"`
}

type StackoverflowUserInfo struct {
	BadgeCounts             StackoverflowUserInfoBadgeCounts `json:"badge_counts"`
	AccountID               int                              `json:"account_id"`
	IsEmployee              bool                             `json:"is_employee"`
	LastAccessDate          int                              `json:"last_access_date"`
	ReputationChangeYear    int                              `json:"reputation_change_year"`
	ReputationChangeQuarter int                              `json:"reputation_change_quarter"`
	ReputationChangeMonth   int                              `json:"reputation_change_month"`
	ReputationChangeWeek    int                              `json:"reputation_change_week"`
	ReputationChangeDay     int                              `json:"reputation_change_day"`
	Reputation              int                              `json:"reputation"`
	CreationDate            int                              `json:"creation_date"`
	UserType                string                           `json:"user_type"`
	UserID                  int                              `json:"user_id"`
	Link                    string                           `json:"link"`
	ProfileImage            string                           `json:"profile_image"`
	DisplayName             string                           `json:"display_name"`
}

type StackoverflowUserInfoResponse struct {
	Items          []StackoverflowUserInfo `json:"items"`
	HasMore        bool                    `json:"has_more"`
	Backoff        int                     `json:"backoff"`
	QuotaMax       int                     `json:"quota_max"`
	QuotaRemaining int                     `json:"quota_remaining"`
}

/*********************QQ**************************/
type QQOAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri" `
	//'grant_type': 'authorization_code',
	GrantType string `json:"grant_type"`
}

type QQOAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type GetQQOpenIDResponse struct {
	ClientID string `json:"client_id"`
	OpenID   string `json:"openid"`
}

type QQUserInfoResponse struct {
	OpenID          string `json:"openid"`
	Ret             int    `json:"ret"`
	Msg             string `json:"msg"`
	IsLost          int    `json:"is_lost"`
	Nickname        string `json:"nickname"`
	Gender          string `json:"gender"`
	GenderType      int    `json:"gender_type"`
	Province        string `json:"province"`
	City            string `json:"city"`
	Year            string `json:"year"`
	Figureurl       string `json:"figureurl"`
	Figureurl1      string `json:"figureurl_1"`
	Figureurl2      string `json:"figureurl_2"`
	FigureurlQQ1    string `json:"figureurl_qq_1"`
	FigureurlQQ2    string `json:"figureurl_qq_2"`
	FigureurlQQ     string `json:"figureurl_qq"`
	IsYellowVip     string `json:"is_yellow_vip"`
	Vip             string `json:"vip"`
	YellowVipLevel  string `json:"yellow_vip_level"`
	Level           string `json:"level"`
	IsYellowYearVip string `json:"is_yellow_year_vip"`
}

type MessageTextToDocxReq struct {
	Text     string `json:"text"`      // 文本内容
	FileName string `json:"file_name"` // 文件名称,必须
	FileType string `json:"file_type"` // 文件类型,docx,txt,md,pdf
	UserID   int    `json:"user_id"`   // 用户ID
}

/**************************gitea***********************/
type GiteaOAuthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type GiteaOAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"` // authorization_code
}
type GiteaUserInfo struct {
	Sub               string      `json:"sub"`
	Name              string      `json:"name"`
	PreferredUsername string      `json:"preferred_username"`
	Email             string      `json:"email"`
	Picture           string      `json:"picture"`
	Groups            interface{} `json:"groups"`
}

/**************************microsoft***********************/
type MicrosoftOAuthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type MicrosoftOAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"` // authorization_code
}

type MicrosoftUserInfo struct {
	OdataContext      string      `json:"@odata.context"`
	BusinessPhones    []string    `json:"businessPhones"`
	DisplayName       string      `json:"displayName"`
	GivenName         string      `json:"givenName"`
	JobTitle          interface{} `json:"jobTitle"`
	Mail              interface{} `json:"mail"`
	MobilePhone       interface{} `json:"mobilePhone"`
	OfficeLocation    interface{} `json:"officeLocation"`
	PreferredLanguage string      `json:"preferredLanguage"`
	Surname           string      `json:"surname"`
	UserPrincipalName string      `json:"userPrincipalName"`
	ID                string      `json:"id"`
}
