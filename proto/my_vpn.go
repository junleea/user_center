package proto

import (
	"github.com/shirou/gopsutil/v3/host"
	"gorm.io/gorm"
	"sync"
	"time"
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

	DPOpCodeAuthUserAdd    = 1
	DPOpCodeAuthUserDel    = 2
	DPOpCodeAuthUserDelAll = 3
	DPOpCodeAuthUserUpdate = 4
	DPOpCodePolicyAdd      = 5
	DPOpCodePolicyUpdate   = 6
	DPOpCodePolicyDel      = 7
	DPOpCodePolicyDelAll   = 8
	DPOpCodeServerDataInfo = 9

	DPOpCodeConfigUpdate = 10
	DPOpCodeServerDel    = 11
)

const (
	VPNClientOpCodeLogout    = 1 //用户注销登录
	VPNClientOpCodeKickOut   = 2 //用户被踢出
	VPNClientEventOpCodePing = 3 //ping
)

type VPNRouter struct {
	Type int    `json:"type" form:"type"` /*4,6,46*/
	IP   string `json:"ip" form:"ip"`
	/*前缀*/
	Prefix int `json:"prefix" form:"prefix"`
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
	AllowUserID     []UserID    `json:"allow_user_id" form:"allow_user_id"`
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

type VPNAuthUserDPInfo struct {
	ID             uint               `json:"id" form:"id"` /*连接id,区分每个连接*/
	UserID         uint               `json:"user_id" form:"user_id"`
	UserName       string             `json:"user_name,omitempty" form:"user_name"`
	PrivateIPv4    string             `json:"private_ipv4,omitempty" form:"private_ipv4"`
	PrivateIPv6    string             `json:"private_ipv6,omitempty" form:"private_ipv6"`
	VPNDPSecret    string             `json:"vpn_dp_secret,omitempty" form:"vpn_dp_secret"` /*dp secret*/
	UUID           string             `json:"uuid,omitempty" form:"uuid"`
	LastUpdateTime int64              `json:"last_update_time,omitempty" form:"last_update_time"`
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
	PrivateIPv4  string `json:"private_ipv4" form:"private_ipv4"`
	IPv4Prefix   int    `json:"ipv4_prefix" form:"ipv4_prefix"`
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
}

type VPNPolicy struct {
	gorm.Model
	VPNPolicyBase
}

type VPNPolicyRequest struct {
	ID uint `json:"id" form:"id"`
	VPNPolicyBase
}

type VPNDPServerEvent struct {
	MsgType        int                   `json:"msg_type" required:"true"`
	OpCode         int                   `json:"op_code" required:"true"`
	AuthUser       *VPNAuthUserDPInfo    `json:"auth_user,omitempty"`
	ServerConfig   *DPServerOnlineConfig `json:"server_config,omitempty"`
	VPNPolicy      *VPNPolicy            `json:"vpn_policy,omitempty"`
	DPServerStatus *VPNDPServerStatus    `json:"dp_server_status,omitempty"`
}

type ClientWsRequest struct {
	ServerID string `json:"server_id" form:"server_id" required:"true"`
	KeyID    uint   `json:"key_id" form:"key_id" required:"true"`
}

type VPNClientEvent struct {
	OpCode   int                `json:"op_code" required:"true"`
	AuthUser *VPNAuthUserDPInfo `json:"auth_user,omitempty"` //更新auth User
}

type VPNClientHostInfo struct {
	host.InfoStat
	ClientVersion string `json:"client_version" form:"client_version"`
}

type ConnectVPNRequest struct {
	ServerID  string             `json:"server_id" form:"server_id" required:"true"`
	SessionID string             `json:"session_id" form:"session_id"`
	HostInfo  *VPNClientHostInfo `json:"host_info" form:"host_info" required:"true"`
}

type VPNDPServerStatus struct {
	Status         int                   `json:"status" required:"true"`
	ReceivePackets int                   `json:"receive_packets" required:"true"`
	SendPackets    int                   `json:"send_packets" required:"true"`
	ReceiveBytes   int                   `json:"receive_bytes" required:"true"`
	SendBytes      int                   `json:"send_bytes" required:"true"`
	LastUpdateTime int64                 `json:"last_update_time" required:"true"`
	OnlineUserInfo []VPNServerOnlineUser `json:"online_user_info" required:"true"`
	rw             sync.RWMutex
}

func (s *VPNDPServerStatus) SetReceiveInfo(receivePackets, receiveBytes int) {
	s.rw.Lock()
	defer s.rw.Unlock()
	s.ReceivePackets = receivePackets
	s.ReceiveBytes = receiveBytes
	s.LastUpdateTime = time.Now().Unix()
}

func (s *VPNDPServerStatus) SetSendInfo(sendPackets, sendBytes int) {
	s.rw.Lock()
	defer s.rw.Unlock()
	s.SendPackets = sendPackets
	s.SendBytes = sendBytes
	s.LastUpdateTime = time.Now().Unix()
}

func (s *VPNDPServerStatus) GetInfo() VPNDPServerStatus {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return VPNDPServerStatus{
		Status:         s.Status,
		ReceivePackets: s.ReceivePackets,
		SendPackets:    s.SendPackets,
		ReceiveBytes:   s.ReceiveBytes,
		SendBytes:      s.SendBytes,
		LastUpdateTime: s.LastUpdateTime,
		OnlineUserInfo: s.OnlineUserInfo,
	}
}

type VPNServerOnlineUser struct {
	SessionID       string `json:"session_id" required:"true"`
	UserID          uint   `json:"user_id" required:"true"`
	UploadPackets   int    `json:"upload_packets" required:"true"`
	DownloadPackets int    `json:"download_packets" required:"true"`
	UploadBytes     int    `json:"upload_bytes" required:"true"`
	DownloadBytes   int    `json:"download_bytes" required:"true"`
	LastUpdateTime  int64  `json:"last_update_time" required:"true"`
	rw              sync.RWMutex
}

func (u *VPNServerOnlineUser) SetUploadInfo(uploadPackets, uploadBytes int) {
	u.rw.Lock()
	defer u.rw.Unlock()
	u.UploadPackets = uploadPackets
	u.UploadBytes = uploadBytes
	u.LastUpdateTime = time.Now().Unix()
}
func (u *VPNServerOnlineUser) SetDownloadInfo(downloadPackets, downloadBytes int) {
	u.rw.Lock()
	defer u.rw.Unlock()
	u.DownloadPackets = downloadPackets
	u.DownloadBytes = downloadBytes
	u.LastUpdateTime = time.Now().Unix()
}

func (u *VPNServerOnlineUser) GetInfo() VPNServerOnlineUser {
	u.rw.RLock()
	defer u.rw.RUnlock()
	return VPNServerOnlineUser{
		SessionID:       u.SessionID,
		UserID:          u.UserID,
		UploadPackets:   u.UploadPackets,
		DownloadPackets: u.DownloadPackets,
		UploadBytes:     u.UploadBytes,
		DownloadBytes:   u.DownloadBytes,
		LastUpdateTime:  u.LastUpdateTime,
	}
}
