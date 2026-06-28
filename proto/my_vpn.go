package proto

import (

	"github.com/shirou/gopsutil/v3/host"
	"gorm.io/gorm"
)

const (
	VPNProtocolTCP           = 1
	VPNProtocolUDP           = 2
	IPTypeV4                 = 4
	IPTypeV6                 = 6
	IPTypeV46                = 46
	DefaultDurationTime      = 30
	VPNDPServerInitStatus    = 0
	VPNDPServerOnlineStatus  = 1
	VPNDPServerOfflineStatus = 2

	VPNDPServerMaxCheckTime = 10 //超过10秒未收到则转为离线
	VPNAuthUserMaxCheckTime = 20 //秒超时未收到则踢出
)

const (
	EncryptionAES128GCM    = "aes-128-gcm"
	EncryptionAES128GCMLen = 16
	EncryptionAES192GCM    = "aes-192-gcm"
	EncryptionAES192GCMLen = 24
	EncryptionAES256GCM    = "aes-256-gcm"
	EncryptionAES256GCMLen = 32
	EncryptionSM4GCM       = "sm4-gcm"
	EncryptionSM4GCMLen    = 16
	EncryptionNone         = "none"
)

const (
	VPNPolicyTypeIP      = 0 //ip
	VPNPolicyTypeNetwork = 1 //网段
	VPNPolicyTypeUserID  = 2 //用户ID
	VPNPolicyTypeGroupID = 3 //用户组ID
)

const (
	DPMsgAuthUserType     = 1
	DPMsgPolicyType       = 2
	DPMsyServerConfigType = 3
	DPMsgServerInfo       = 4
	CPVPNTimeType         = 5 //vpn time download, client / dp server same
	DPMsgServerControlType = 6 //server control

	DPOpCodeAuthUserAdd    = 1
	DPOpCodeAuthUserDel    = 2
	DPOpCodeAuthUserDelAll = 3
	DPOpCodeAuthUserUpdate = 4
	DPOpCodePolicyAdd      = 5
	DPOpCodePolicyUpdate   = 6
	DPOpCodePolicyDel      = 7
	DPOpCodePolicyDelAll   = 8
	DPOpCodeServerDataInfo = 9
	DPOpCodeServerUpdate = 10  // 更新服务器程序
	DPOpCodeDPServerInfo = 11  //上传服务器信息
	DPOpCodeAuthUserRekey = 12 // auth user rekey

	DPOpCodeConfigUpdate = 13
	DPOpCodeServerDel    = 14
	DPOpCodeRestart       = 15
)


const (
	VPNClientOpCodeLogout         = 1 //用户注销登录
	VPNClientOpCodeKickOut        = 2 //用户被踢出
	VPNClientEventOpCodePing      = 3 //ping
	VPNClientEventOOpCodeHostInfo = 4 //host info upload
	VPNClientEventOOpCodeRekey    = 6 //rekey
)

const (
	VPNRouterTypeGlobal = 0 /*全局路由*/
	VPNRouterTypeUser   = 1 /*用户路由*/
	VPNRouterTypeGroup  = 2 /*用户组路由*/
)
const (

	RekeyDuration int64 = (60 * 60 * 1)

	PolicyUserToSelf uint = 4294967212
	PolicyUserAll uint = 4294967223
)

type VPNRouter struct {
	Type         int    `json:"type" form:"type"`                 /*4,6,46*/
	IP           string `json:"ip" form:"ip"`
	Prefix       int    `json:"prefix" form:"prefix"`             /*前缀*/
	Metric       int    `json:"metric" form:"metric"`             /*默认35*/
	RouterType   int    `json:"router_type" form:"router_type"`   /*路由类型：0-全局路由，1-用户路由，2-用户组路由*/
	TargetID     int    `json:"target_id" form:"target_id"`       /*目标ID：0-全局，>0-用户ID或用户组ID（根据RouterType区分）*/
}

type StringValue struct {
	Value string `json:"value" form:"value"`
}

type DPServerOnlineConfig struct {
	ServerConfig
	IPv4Address     string            `json:"ipv4_address" form:"ipv4_address"`
	IPv4Prefix      int               `json:"ipv4_prefix" form:"ipv4_prefix"`
	IPv6Address     string            `json:"ipv6_address" form:"ipv6_address"`
	IPv6Prefix      int               `json:"ipv6_prefix" form:"ipv6_prefix"`
	IPv4MTU         int               `json:"ipv4_mtu" form:"ipv4_mtu"`
	IPv6MTU         int               `json:"ipv6_mtu" form:"ipv6_mtu"`
	UploadLimit     int               `json:"upload_limit" form:"upload_limit"`     /*上传限速，Kbps, 默认：1024Kbps*/
	DownloadLimit   int               `json:"download_limit" form:"download_limit"` /*下载限速，Kbps, 默认：1024Kbps*/
	Status          int               `json:"status" form:"status"`
	LastServerCheck int64             `json:"last_server_check" form:"last_server_check"`
	VPNStatus       VPNDPServerStatus `json:"vpn_status" form:"vpn_status"`
	DPServerInfo    VPNDPServerInfo   `json:"dp_info" form:"dp_info"`
}

type ServerConfigBase struct {
	Name            string      `json:"name" form:"name"`
	ServerID        string      `json:"server_id" form:"server_id"`
	ServerIP        string      `json:"server_ip" form:"server_ip"`
	ServerIPV6      string      `json:"server_ipv6" form:"server_ipv6"`
	ServerIPType    int         `json:"server_ip_type" form:"server_ip_type"`
	ServerInfo      string      `json:"server_info" form:"server_info"`
	UDPPort         int         `json:"udp_port" form:"udp_port"` /*udp port*/
	TCPPort         int         `json:"tcp_port" form:"tcp_port"`
	Protocol        int         `json:"protocol" form:"protocol"` /* 1: tcp, 2: udp */
	IPType          int         `json:"ip_type" form:"ip_type"`   /* 4, 6, 46 */
	IPv4AddressPool string      `json:"ipv4_address_pool" form:"ipv4_address_pool"`
	IPv6AddressPool string      `json:"ipv6_address_pool" form:"ipv6_address_pool"`
	DNSServer       string      `json:"dns_server" form:"dns_server"`
	Tunnel          string      `json:"tunnel" form:"tunnel"`
	Encryption      string      `json:"encryption" form:"encryption"` /*加密算法：aes-128-gcm, aes-192-gcm, aes-256-gcm, SM4-GCM*/
	Hash            string      `json:"hash" form:"hash"`             /*摘要算法：sha256, sha512, md5, sm3*/
	UserMaxDevice   int         `json:"user_max_device" form:"user_max_device"`
	DurationTime    int         `json:"duration_time" form:"duration_time"`       /*空闲时长，秒*/
	NoPolicyAction  int         `json:"no_policy_action" form:"no_policy_action"` //策略匹配失败时的动作，0-deny,1-permit
	IPv4Router      []VPNRouter `json:"ipv4_router" form:"ipv4_router"`
	IPv6Router      []VPNRouter `json:"ipv6_router" form:"ipv6_router"`
}

type VPNAllowUser struct {
	UserID uint `json:"user_id" form:"user_id"` //用户/用户组ID
	MaxConnections int `json:"max_connections" form:"max_connections"` //最大连接数，0不限
	MaxUpload int `json:"max_upload" form:"max_upload"` //上传限速，Kbps, 默认：1024Kbps
	MaxDownload int `json:"max_download" form:"max_download"` //下载限速，Kbps, 默认：1024Kbps
}

type ServerConfig struct {
	Name            string      `json:"name" form:"name"`
	ServerID        string      `json:"server_id" form:"server_id"`
	ServerIP        string      `json:"server_ip" form:"server_ip"`
	ServerIPV6      string      `json:"server_ipv6" form:"server_ipv6"`
	ServerIPType    int         `json:"server_ip_type" form:"server_ip_type"`
	ServerInfo      string      `json:"server_info" form:"server_info"`
	UDPPort         int         `json:"udp_port" form:"udp_port"` /*udp port*/
	TCPPort         int         `json:"tcp_port" form:"tcp_port"`
	Protocol        int         `json:"protocol" form:"protocol"` /* 1: tcp, 2: udp */
	IPType          int         `json:"ip_type" form:"ip_type"`   /* 4, 6, 46 */
	IPv4AddressPool string      `json:"ipv4_address_pool" form:"ipv4_address_pool"`
	IPv6AddressPool string      `json:"ipv6_address_pool" form:"ipv6_address_pool"`
	DNSServer       string      `json:"dns_server" form:"dns_server"`
	Tunnel          string      `json:"tunnel" form:"tunnel"`
	AllowUser      []VPNAllowUser `json:"allow_user" form:"allow_user"`
	Encryption      string      `json:"encryption" form:"encryption"` /*加密算法：aes-128-gcm, aes-192-gcm, aes-256-gcm, SM4-GCM*/
	Hash            string      `json:"hash" form:"hash"`             /*摘要算法：sha256, sha512, md5, sm3*/
	UserMaxDevice   int         `json:"user_max_device" form:"user_max_device"`
	DurationTime    int         `json:"duration_time" form:"duration_time"`       /*空闲时长，秒*/
	NoPolicyAction  int         `json:"no_policy_action" form:"no_policy_action"` //策略匹配失败时的动作，0-deny,1-permit
	IPv4Router      []VPNRouter `json:"ipv4_router" form:"ipv4_router"`
	IPv6Router      []VPNRouter `json:"ipv6_router" form:"ipv6_router"`
}

type SetServerConfigRequest struct {
	ServerID   string       `json:"server_id" form:"server_id" required:"true"`
	ServerIP   string       `json:"server_ip" form:"server_ip"`
	ServerInfo string       `json:"server_info" form:"server_info"`
	Config     ServerConfig `json:"config" form:"config"`
}

type TunnelConfig struct {
	TunnelName    string `json:"tunnel_name" form:"tunnel_name"`
	AutoIPv4      bool   `json:"auto_ipv4" form:"auto_ipv4"` /*自动获取ipv4, 默认：false*/
	AutoIPv6      bool   `json:"auto_ipv6" form:"auto_ipv6"` /*自动获取ipv6, 默认：false*/
	IPv4Address   string `json:"ipv4_address" form:"ipv4_address"`
	IPv6Address   string `json:"ipv6_address" form:"ipv6_address"`
	IPv4MTU       int    `json:"ipv4_mtu" form:"ipv4_mtu"`
	IPv6MTU       int    `json:"ipv6_mtu" form:"ipv6_mtu"`
	UploadLimit   int    `json:"upload_limit" form:"upload_limit"`     /*上传限速，Kbps, 默认：1024Kbps*/
	DownloadLimit int    `json:"download_limit" form:"download_limit"` /*下载限速，Kbps, 默认：1024Kbps*/
}

type UserIDBindIP struct {
	UserID int    `json:"user_id" form:"user_id"`
	BindIP string `json:"bind_ip" form:"bind_ip"`
}

type AddressPool struct {
	StartIP   string         `json:"start_ip" form:"start_ip"`
	EndIP     string         `json:"end_ip" form:"end_ip"`
	Prefix    int            `json:"prefix" form:"prefix"`
	DNSIP     []StringValue  `json:"dns_ip" form:"dns_ip"`
	IPBind    []UserIDBindIP `json:"ip_bind" form:"ip_bind"`
	IPBindMap map[int]int    `json:"-" form:"-"`
}

type AddressPoolConfig struct {
	IPv4AddressPool AddressPool `json:"ipv4_address_pool" form:"ipv4_address_pool"`
	IPv6AddressPool AddressPool `json:"ipv6_address_pool" form:"ipv6_address_pool"`
}

type AddressPoolRequest struct {
	PoolName string            `json:"pool_name" form:"pool_name" required:"true"`
	Config   AddressPoolConfig `json:"config" form:"config"`
}

type TunnelRequestAndResponse struct {
	TunnelName string       `json:"tunnel_name" form:"tunnel_name" required:"true"`
	Config     TunnelConfig `json:"config" form:"config"`
}

type UserClientRequestVPNOnlineResponse struct {
	ServerID     string `json:"server_id" form:"server_id"`
	ServerIP     string `json:"server_ip" form:"server_ip"`
	ServerIPV6   string `json:"server_ipv6" form:"server_ipv6"`
	ServerIPType int    `json:"server_ip_type" form:"server_ip_type"`
	UDPPort      int    `json:"udp_port" form:"udp_port"` /*udp port*/
	TCPPort      int    `json:"tcp_port" form:"tcp_port"`
	Protocol     int    `json:"protocol" form:"protocol"` /* 1: tcp, 2: udp */
	IPType       int    `json:"ip_type" form:"ip_type"`   /* 4, 6, 46 */

	/* for client pricate ip */
	ClientIPv4    string `json:"client_ipv4" form:"client_ipv4"`
	ClientIPv6    string `json:"client_ipv6" form:"client_ipv6"`
	IPv4MTU       string `json:"ipv4_mtu" form:"ipv4_mtu"`
	IPv6MTU       string `json:"ipv6_mtu" form:"ipv6_mtu"`
	UploadLimit   int    `json:"upload_limit" form:"upload_limit"`     /*上传限速，Kbps, 默认：1024Kbps*/
	DownloadLimit int    `json:"download_limit" form:"download_limit"` /*下载限速，Kbps, 默认：1024Kbps*/

	/*dp secret*/
	VPNDPSecret string        `json:"vpn_dp_secret" form:"vpn_dp_secret"`
	IPv4Router  []StringValue `json:"ipv4_router" form:"ipv4_router"`
	IPv6Router  []StringValue `json:"ipv6_router" form:"ipv6_router"`

	Encryption string `json:"encryption" form:"encryption"` /*加密算法：aes-128-gcm, aes-192-gcm, aes-256-gcm, SM4-GCM*/
	Hash       string `json:"hash" form:"hash"`             /*摘要算法：sha256, sha512, md5, sm3*/

	TunnelGatewayIPv4 string `json:"tunnel_gateway_ipv4" form:"tunnel_gateway_ipv4"` /*tunnel server gateway ip*/
	TunnelGatewayIPv6 string `json:"tunnel_gateway_ipv6" form:"tunnel_gateway_ipv6"`
}

type ServerRequestVPNServerConfig struct {
	ServerID string `json:"server_id" form:"server_id"`
	ServerIP string `json:"server_ip" form:"server_ip"`
	UDPPort  int    `json:"udp_port" form:"udp_port"` /*udp port*/
	TCPPort  int    `json:"tcp_port" form:"tcp_port"`
	Protocol int    `json:"protocol" form:"protocol"` /* 1: tcp, 2: udp */
	IPType   int    `json:"ip_type" form:"ip_type"`   /* 4, 6, 46 */

	IPv4MTU       string `json:"ipv4_mtu" form:"ipv4_mtu"`
	IPv6MTU       string `json:"ipv6_mtu" form:"ipv6_mtu"`
	UploadLimit   int    `json:"upload_limit" form:"upload_limit"`     /*上传限速，Kbps, 默认：1024Kbps*/
	DownloadLimit int    `json:"download_limit" form:"download_limit"` /*下载限速，Kbps, 默认：1024Kbps*/

	IPv4Router []StringValue `json:"ipv4_router" form:"ipv4_router"`
	IPv6Router []StringValue `json:"ipv6_router" form:"ipv6_router"`

	Encryption string `json:"encryption" form:"encryption"` /*加密算法：aes-128-gcm, aes-192-gcm, aes-256-gcm, SM4-GCM*/
	Hash       string `json:"hash" form:"hash"`             /*摘要算法：sha256, sha512, md5, sm3*/

	TunnelGatewayIPv4 string `json:"tunnel_gateway_ipv4" form:"tunnel_gateway_ipv4"` /*tunnel server gateway ip*/
	TunnelGatewayIPv6 string `json:"tunnel_gateway_ipv6" form:"tunnel_gateway_ipv6"`
}

type SupportServerInfo struct {
	ServerID   string `json:"server_id" form:"server_id"`
	ServerIP   string `json:"server_ip" form:"server_ip"`
	ServerInfo string `json:"server_info" form:"server_info"`
}

type UserSupportVPNServerResponse struct {
	SupportServer []SupportServerInfo `json:"support_server" form:"support_server"`
}

const (
	VPNServerConfigTypeServer      = 0
	VPNServerConfigTypeAddressPool = 1
	VPNServerConfigTypeTunnel      = 2
)

const (
	UserLoginEvent = 1
	UserLogoutEvent = 2
	VPNAdminKickOutEvent = 3
	VPNCientTimeoutKickOutEvent = 4
)
/*my vpn user login info*/
type MyVPNUserLoginInfo struct {
	gorm.Model
	UserID    uint   `json:"user_id" form:"user_id"`
	UserName  string `json:"user_name" form:"user_name"`
	HostID    string `json:"host_id" form:"host_id"`
	ServerID  string `json:"server_id" form:"server_id"`
	SessionID string `json:"session_id" form:"session_id"`
	ClientIP  string `json:"client_ip" form:"client_ip"`
	PrivateIP string `json:"private_ip" form:"private_ip"`
	Event 	uint    `json:"event" form:"event"` /*1: login, 2: logout, */
}

/*my vpn server config*/
type MyVPNServerConfig struct {
	gorm.Model
	Type  int    `json:"type" form:"type"`   /*config type*/
	Attr  string `json:"attr" form:"attr"`   /*config attr, different, server:server_id, Pool: pool name,Tunnel: tunnel name*/
	Value string `json:"value" form:"value"` /*config value, json format*/
}

type SupportVPNServer struct {
	Name       string `json:"name"`
	ServerID   string `json:"server_id" form:"server_id"`
	ServerIP   string `json:"server_ip" form:"server_ip"`
	ServerInfo string `json:"server_info" form:"server_info"`
	ServerIPV6 string `json:"server_ipv6"`
	UDPPort    int    `json:"udp_port" form:"udp_port"` /*udp port*/
	TCPPort    int    `json:"tcp_port" form:"tcp_port"`
	Protocol   int    `json:"protocol" form:"protocol"` /* 1: tcp, 2: udp */
}
type UserGroupInfo struct {
	UserGroupID uint `json:"user_group_id" form:"user_group_id"`	
}
type VPNAuthUserDPInfo struct {
	ID             uint               `json:"id" form:"id"` /*连接id,区分每个连接*/
	UserID         uint               `json:"user_id" form:"user_id"`
	UserName       string             `json:"user_name,omitempty" form:"user_name"`
	PrivateIPv4    string             `json:"private_ipv4,omitempty" form:"private_ipv4"`
	PrivateIPv6    string             `json:"private_ipv6,omitempty" form:"private_ipv6"`
	VPNDPSecret    string             `json:"vpn_dp_secret,omitempty" form:"vpn_dp_secret"` /*dp secret*/
	SecretKeyTime  int64             `json:"secret_key_time" form:"secret_key_time"`
	UUID           string             `json:"uuid,omitempty" form:"uuid"`
	LastUpdateTime int64              `json:"last_update_time,omitempty" form:"last_update_time"`
	MaxUpload	   int                `json:"max_upload,omitempty" form:"max_upload"`         /*上传限速，Kbps, 默认：1024Kbps*/
	MaxDownload	   int                `json:"max_download,omitempty" form:"max_download"`     /*下载限速，Kbps, 默认：1024Kbps*/
	OnlineTime	   int64              `json:"online_time,omitempty" form:"online_time"`
	ClientIP       string             `json:"client_ip,omitempty" form:"client_ip"`
	UserGroupInfo  []UserGroupInfo 	  `json:"user_group_info,omitempty" form:"user_group_info"`
	HostInfo       *VPNClientHostInfo `json:"host_info,omitempty" form:"host_info"`
}

type GetClientConfigOnlineResponse struct {
	ID           uint   `json:"id" form:"id"`
	UserID       uint   `json:"user_id" form:"user_id"`
	ServerID     string `json:"server_id" form:"server_id"`
	ServerIP     string `json:"server_ip" form:"server_ip"`
	ServerIPV6   string `json:"server_ipv6" form:"server_ipv6"`
	ServerIPType int    `json:"server_ip_type" form:"server_ip_type"`
	UDPPort      int    `json:"udp_port" form:"udp_port"` /*dp, udp port*/
	TCPPort      int    `json:"tcp_port" form:"tcp_port"` /*dp, tcp port*/
	Protocol     int    `json:"protocol" form:"protocol"` /* 1: tcp, 2: udp */
	IPType       int    `json:"ip_type" form:"ip_type"`   /* 4, 6, 46 */
	DNSServer    string `json:"dns_server" form:"dns_server"`
	IPv4Prefix   int    `json:"ipv4_prefix" form:"ipv4_prefix"`
	PrivateIPv4  string `json:"private_ipv4" form:"private_ipv4"`
	PrivateIPv6  string `json:"private_ipv6" form:"private_ipv6"`
	IPv6Prefix   int    `json:"ipv6_prefix" form:"ipv6_prefix"`
	IPv4MTU      int    `json:"ipv4_mtu" form:"ipv4_mtu"`
	IPv6MTU      int    `json:"ipv6_mtu" form:"ipv6_mtu"`
	SessionID    string `json:"session_id" form:"session_id"`
	TunnelIP     string `json:"tunnel_ip" form:"tunnel_ip"`
	Gateway      string `json:"gateway" form:"gateway"`

	UploadLimit   int    `json:"upload_limit" form:"upload_limit"`     /*上传限速，Kbps, 默认：1024Kbps*/
	DownloadLimit int    `json:"download_limit" form:"download_limit"` /*下载限速，Kbps, 默认：1024Kbps*/
	VPNDPSecret   string `json:"vpn_dp_secret" form:"vpn_dp_secret"`   /*dp secret*/

	Encryption string      `json:"encryption" form:"encryption"` /*加密算法：aes-128-gcm, aes-192-gcm, aes-256-gcm, SM4-GCM*/
	Hash       string      `json:"hash" form:"hash"`             /*摘要算法：sha256, sha512, md5, sm3*/
	IPv4Router []VPNRouter `json:"ipv4_router" form:"ipv4_router"`
	IPv6Router []VPNRouter `json:"ipv6_router" form:"ipv6_router"`
}

type GetOnlineServerWithAuthUser struct {
	ServerConfig DPServerOnlineConfig    `json:"server_config"`
	AuthUser     []VPNAuthUserDPInfoList `json:"auth_user"`
}

type VPNAuthUserDPInfoList struct {
	UserID   uint                `json:"user_id"`
	AuthUser []VPNAuthUserDPInfo `json:"auth_user"`
}

type SetVPNClientStatusReq struct {
	UUID     string `json:"uuid" form:"uuid" required:"true"` //会话id
	ServerID string `json:"server_id" form:"server_id" required:"true"`
}

type SetVPNServerStatusReq struct {
	ServerID string `json:"server_id" form:"server_id" required:"true"`
	Status   int    `json:"status" form:"status" required:"true"`
}

type VPNPolicyBase struct {
	Name      string `json:"name" form:"name" required:"true"`
	ServerID  string `json:"server_id,omitempty" form:"server_id"  required:"true"`
	IPType    uint   `json:"ip_type" form:"ip_type"  required:"true"`   // 4, 6
	SrcType   uint   `json:"src_type" form:"src_type"  required:"true"` // 0-ip,1-network, 2-userID, 3-groupID
	SrcIP     string `json:"src_ip,omitempty" form:"src_ip"`            //type 1, set 0.0.0.0/0 is all
	SrcUserID int    `json:"src_user_id" form:"src_user_id"`            // 0-all, more than 0, user
	DstType   uint   `json:"dst_type" form:"dst_type"  required:"true"` // 0-ip,1-network, 2-userID, 3-groupID
	DstIP     string `json:"dst_ip,omitempty" form:"dst_ip"`
	DstUserID int    `json:"dst_user_id" form:"dst_user_id"`
	//协议
	Protocol uint `json:"protocol" form:"protocol" required:"true"` //0:is all, 1-ICMP, 17-UDP etc.
	//操作
	Action uint   `json:"action" form:"action" required:"true"` // 0-deny, 1-permit
	Info   string `json:"info,omitempty" form:"info"`

	// 新增：优先级，数值越小优先级越高，默认100
	Priority int `json:"priority" form:"priority"` 
}

type VPNPolicy struct {
	gorm.Model
	VPNPolicyBase
}

type VPNPolicyRequest struct {
	ID uint `json:"id" form:"id"`
	VPNPolicyBase
}

type VPNDPServerInfo struct {
	BuildTime string `json:"build_time" required:"true"`
	Version string `json:"version" required:"true"`
	GitHash string `json:"git_hash" required:"true"`
}

type VPNDPServerEvent struct {
	MsgType        int                   `json:"msg_type" required:"true"`
	OpCode         int                   `json:"op_code" required:"true"`
	AuthUser       *VPNAuthUserDPInfo    `json:"auth_user,omitempty"`
	ServerConfig   *DPServerOnlineConfig `json:"server_config,omitempty"`
	VPNPolicy      *VPNPolicy            `json:"vpn_policy,omitempty"`
	DPServerStatus *VPNDPServerStatus    `json:"dp_server_status,omitempty"`
	DPServerInfo *VPNDPServerInfo      `json:"dp_server_info,omitempty"`
	VPNTime        uint32                `json:"vpn_time,omitempty"`
}

type ClientWsRequest struct {
	ServerID string `json:"server_id" form:"server_id" required:"true"`
	KeyID    uint   `json:"key_id" form:"key_id" required:"true"`
}

type VPNClientEvent struct {
	OpCode   int                `json:"op_code" required:"true"`
	AuthUser *VPNAuthUserDPInfo `json:"auth_user,omitempty"` //更新auth User
	HostInfo *VPNClientHostInfo `json:"host_info,omitempty"`
	VPNTime  uint32             `json:"vpn_time,omitempty"`
}

type VPNClientHostInfo struct {
	host.InfoStat
	ComputerInfo
	ClientVersion string `json:"client_version" form:"client_version"`
}

type ComputerInfo struct {
	MacAddress    string `json:"mac_address" form:"mac_address"`
	BoardSN string `json:"board_sn" form:"board_sn"` //主板序列号
	DiskSN string `json:"disk_sn" form:"disk_sn"` //硬盘序列号
	CpuInfo string `json:"cpu_info" form:"cpu_info"` //cpu信息
	HardwareID string `json:"hardware_id" form:"hardware_id"` //硬件id
}

type VPNHostInfoModel struct {
	gorm.Model
	host.InfoStat
	ComputerInfo
}

type VPNHostInfoListResponse struct {
	Total    int64                    `json:"total"`
	List     []VPNHostInfoModel `json:"list"`
	Page     int                      `json:"page"`
	PageSize int                      `json:"page_size"`
}

type ConnectVPNRequest struct {
	ServerID  string             `json:"server_id" form:"server_id" required:"true"`
	SessionID string             `json:"session_id" form:"session_id"`
	HostInfo  *VPNClientHostInfo `json:"host_info" form:"host_info" required:"true"`
}

type VPNDPServerStatus struct {
	Status         int                   `json:"status" required:"true"`
	StartTime      int64                 `json:"start_time" required:"true"`
	ReceivePackets int64                 `json:"receive_packets" required:"true"`
	SendPackets    int64                 `json:"send_packets" required:"true"`
	ReceiveBytes   int64                 `json:"receive_bytes" required:"true"`
	SendBytes      int64                 `json:"send_bytes" required:"true"`
	LastUpdateTime int64                 `json:"last_update_time" required:"true"`
	OnlineUserInfo []VPNServerOnlineUser `json:"online_user_info" required:"true"`
	CurrentSession int64 				 `json:"current_session" required:"true"`
	PolicyHitCount int 					 `json:"policy_hit_count" required:"true"`
}

func (s *VPNDPServerStatus) GetInfo() VPNDPServerStatus {
	return VPNDPServerStatus{
		Status:         s.Status,
		ReceivePackets: s.ReceivePackets,
		SendPackets:    s.SendPackets,
		ReceiveBytes:   s.ReceiveBytes,
		SendBytes:      s.SendBytes,
		LastUpdateTime: s.LastUpdateTime,
		OnlineUserInfo: s.OnlineUserInfo,
		StartTime: 		s.StartTime,
		CurrentSession: s.CurrentSession,
		PolicyHitCount: s.PolicyHitCount,
	}
}

type VPNServerOnlineUser struct {
	SessionID       string `json:"session_id" required:"true"`
	UserID          uint   `json:"user_id" required:"true"`
	UploadPackets   int64  `json:"upload_packets" required:"true"`
	DownloadPackets int64  `json:"download_packets" required:"true"`
	UploadBytes     int64  `json:"upload_bytes" required:"true"`
	DownloadBytes   int64  `json:"download_bytes" required:"true"`
	LastUpdateTime  int64  `json:"last_update_time" required:"true"`
	ClientIP        string `json:"client_ip" required:"true"` //客户端IP:端口
}

func (u *VPNServerOnlineUser) GetInfo() VPNServerOnlineUser {
	return VPNServerOnlineUser{
		SessionID:       u.SessionID,
		UserID:          u.UserID,
		UploadPackets:   u.UploadPackets,
		DownloadPackets: u.DownloadPackets,
		UploadBytes:     u.UploadBytes,
		DownloadBytes:   u.DownloadBytes,
		LastUpdateTime:  u.LastUpdateTime,
		ClientIP:        u.ClientIP,
	}
}
