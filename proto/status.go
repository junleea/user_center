package proto

const (
	SuccessCode = 0 // 成功

	// 通用错误码
	ErrorCode           = 1  // 未知错误或服务器内部错误
	ParameterError      = 9  // 请求参数解析错误
	OperationFailed     = 17 // 数据库数据操作失败
	DataNotFound        = 14 // 查询数据失败
	InternalServerError = 10 // 服务器内部错误

	// Token相关错误码
	TokenInvalid         = 2  // Token失效，未登录
	TokenIsNull          = 3  // Token为空
	TokenExpired         = 4  // Token已过期
	TokenGenerationError = 5  // Token生成错误
	TokenParseError      = 19 // Token解析错误

	// 用户名密码相关错误码
	UsernameOrPasswordError = 6  // 用户名或密码错误
	UsernameExists          = 7  // 用户名已存在
	PermissionDenied        = 21 // 权限不足

	// Redis相关错误码
	RedisSetError = 8  // 设置redis错误
	RedisGetError = 20 // 获取redis错误

	// 视频操作相关错误码
	VideoDelayOperationFailed = 11 // 视频延迟操作失败
	VideoDeleteFailed         = 12 // 视频删除失败

	// 设备操作相关错误码
	DeviceRestartFailed = 13 // 设备重启失败
	DeviceAddFailed     = 15 // 设备添加失败
	DeviceUpdateFailed  = 16 // 设备修改失败

	// 撤销操作相关错误码
	RevokeOperation            = 30 // 撤销
	RevokeDelayOperationFailed = 31 // 撤销延迟操作失败
	RevokeOperationFailed      = 32 // 撤销操作失败

	// UUID相关错误码
	UUIDNotFound = 18 // uuid不存在

	//Tool
	NoRedisPermissions  = 51
	NoRunPermissions    = 52
	NoDevicePermissions = 53
	NoPermission        = 54

	//消息错误码
	MsgSendFailed = 61 // 消息发送失败

	//文件错误码
	FileNotFound         = 71 // 文件不存在
	FileUploadFailed     = 72 // 文件上传失败
	SaveFileInfoFailed   = 73 // 保存文件信息失败
	SaveFileFailed       = 74 // 保存文件失败
	UploadFileFailed     = 75 // 上传文件失败
	NoUploadPermissions  = 76 // 无上传权限
	DeleteFileFailed     = 77 // 删除文件失败
	DeleteFileInfoFailed = 78 // 删除文件信息失败

	DataFormatError = 80 // 数据格式错误

	AddConfigFileFailed    = 90 // 添加配置文件失败
	UpdateConfigFailed     = 91 // 更新配置失败
	DeleteConfigFailed     = 92 // 删除配置失败
	SearchConfigFileFailed = 93 // 获取配置失败

	ShellCreateFailed = 100 // 创建shell失败
	ShellUpdateFailed = 101 // 更新shell失败
	ShellDeleteFailed = 102 // 删除shell失败
	ShellSearchFailed = 103 // 获取shell失败

	ModelCreateFailed = 110 // 创建模型失败
	ModelUpdateFailed = 111 // 更新模型失败
	ModelDeleteFailed = 112 // 删除模型失败
	ModelSearchFailed = 113 // 获取模型失败

	SessionSearchFailed = 120 // 获取会话失败
	SessionCreateFailed = 121 // 创建会话失败
	SessionDeleteFailed = 122 // 删除会话失败
	SessionUpdateFailed = 123 // 更新会话失败

	FuncModelCreateFailed = 130 // 创建功能模型失败
	FuncModelUpdateFailed = 131 // 更新功能模型失败
	FuncModelDeleteFailed = 132 // 删除功能模型失败
	FuncModelSearchFailed = 133 // 获取功能模型失败

	GetSparkCreatePPTStatusFailed = 140 // 获取spark创建ppt状态失败

	//下面是ws消息错误码
	WSKBaseServerError  = 150 // ws知识库服务器错误
	WSKBaseSessionError = 151 // ws知识库会话错误

	//第三方登录
	ThirdPartyLoginUUIDInvalid = 161 //第三方登录uuid失效
	ThirdPartyAddUserHasBinded = 162 //第三方登录用户已绑定
	//第三方用户未绑定
	ThirdPartyUserNotBinded = 163 //第三方登录用户未绑定

)

const (
	// 代码中使用常量定义
	UserAndModelMsgType = 2 // 用户与模型消息类型
	MsgHasRead          = 1 // 消息已读

	//用户发到模型
	UserToModelMsgType = 3
	//模型发到用户
	ModelToUserMsgType = 4

	//用户发送图片对话
	UserToModelImageMsgType = 3
	UserToModelFileMsgType  = 3
	//模型发送文件对话
	ModelToUserFileMsgType = 4
	//用户与模型制作ppt的会话
	UserToModelPPTMsgType = 5 //用户与模型制作ppt的会话
)

// 豆包返回的数据停止原因
const (
	FinishReasonStop          = "stop"
	FinishReasonLength        = "length"
	FinishReasonFunctionCall  = "function_call"
	FinishReasonToolCalls     = "tool_calls"
	FinishReasonContentFilter = "content_filter"
	FinishReasonNull          = "null"
)

// spark 角色
const (
	SparkRoleUser      = "user"
	SparkRoleAssistant = "assistant"
	SparRoleSystem     = "system"
)

// 支持模型类型
const (
	ModelTypeSpark                  = "spark"
	ModelTypeDouBao                 = "doubao"
	ModelTypeOllama                 = "ollama"
	ModelTypeQianfan                = "qianfan"
	ModelTypeTongyi                 = "tongyi"
	ModelTypeHunyuan                = "hunyuan"
	ModelTypeGemini                 = "gemini"
	KnowledgeBaseServerResponseType = "kbase_query_resp"
)

// 其它
const (
	SparkContextLength  = 6
	DouBaoContextLength = 6
)

// 模型参数
const (
	DefaultTemperature = 0.5
	DefaultMaxTokens   = 4096
	DefaultTopK        = 0.5
	DefaultTopP        = 0.8
)

// 文件
const (
	UserFileTypeIM     = "im"     // IM文件
	UserFileTypeAvatar = "avatar" // 用户头像
	UserFileTypeFile   = "file"   // 通用文件
	UserFileTypeConfig = "config" // 配置文件
	UserMaxUploadSize  = 1024 * 1024 * 100

	KnowledgeBaseFunction = "kbase-chat" // 知识库功能
)

// 会话类型
const (
	SessionTypeUserWithModelGeneration = 1 // 用户与模型通用会话
	SessionTypeUserPrompt              = 2 // 用户与模型提示词
	SessionTypeUserCreatePPT           = 3 // 用户与模型制作PPT
	SessionTypeKnowledgeBase           = 4 // 用户与知识库
)

// 文件类型（文本、图片）
const (
	DownloadFileBaseURL = "https://pm.ljsea.top/tool/file/"
	FileTypeText        = "text_file"
	FileTypeImage       = "image_file"
)

// 第三方登录设计url
const (
	GitHuAuthorizeBaseUrl         = "https://github.com/login/oauth/authorize"
	QQAuthorizeBaseUrl            = "https://graph.qq.com/oauth2.0/authorize"
	GiteeAuthorizeBaseUrl         = "https://gitee.com/oauth/authorize"
	GoogleAuthorizeBaseUrl        = "https://accounts.google.com/o/oauth2/v2/auth"
	FacebookAuthorizeBaseUrl      = "https://www.facebook.com/v22.0/dialog/oauth"
	StackOverflowAuthorizeBaseUrl = "https://stackoverflow.com/oauth"
	MyGiteaAuthorizeBaseUrl       = "https://gogs.ljsea.top/login/oauth/authorize"
	GiteaAuthorizeBaseUrl         = "https://gitea.com/login/oauth/authorize"
)

// 百度千帆
const (
	QianfanAccessKey = "e1757df9133649f59cb1ef45667049b7"
	QianfanSecretKey = "6c0ee3154db14d99ad2b66c5623277fb"
)

// 千帆 角色
const (
	QianfanRoleUser  = "user"
	QianfanAssistant = "assistant"
	QianfanSystem    = "system"
)
