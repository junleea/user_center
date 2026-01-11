package proto

import (
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
	IPv4Address     string `json:"ipv4_address" form:"ipv4_address"`
	IPv4Prefix      int    `json:"ipv4_prefix" form:"ipv4_prefix"`
	IPv6Address     string `json:"ipv6_address" form:"ipv6_address"`
	IPv6Prefix      int    `json:"ipv6_prefix" form:"ipv6_prefix"`
	IPv4MTU         int    `json:"ipv4_mtu" form:"ipv4_mtu"`
	IPv6MTU         int    `json:"ipv6_mtu" form:"ipv6_mtu"`
	UploadLimit     int    `json:"upload_limit" form:"upload_limit"`     /*上传限速，Kbps, 默认：1024Kbps*/
	DownloadLimit   int    `json:"download_limit" form:"download_limit"` /*下载限速，Kbps, 默认：1024Kbps*/
	Status          int    `json:"status" form:"status"`
	LastServerCheck int64  `json:"last_server_check" form:"last_server_check"`
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
	DurationTime    int         `json:"duration_time" form:"duration_time"` /*空闲时长，秒*/
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
	ServerID   string `json:"server_id" form:"server_id"`
	ServerIP   string `json:"server_ip" form:"server_ip"`
	ServerInfo string `json:"server_info" form:"server_info"`
}

type VPNAuthUserDPInfo struct {
	ID             uint   `json:"id" form:"id"` /*连接id,区分每个连接*/
	UserID         uint   `json:"user_id" form:"user_id"`
	UserName       string `json:"user_name" form:"user_name"`
	PrivateIPv4    string `json:"private_ipv4" form:"private_ipv4"`
	PrivateIPv6    string `json:"private_ipv6" form:"private_ipv6"`
	VPNDPSecret    string `json:"vpn_dp_secret" form:"vpn_dp_secret"` /*dp secret*/
	UUID           string `json:"uuid" form:"uuid"`
	LastUpdateTime int64  `json:"last_update_time" form:"last_update_time"`
}

type GetClientConfigOnlineResponse struct {
	ID           uint   `json:"id" form:"id"`
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
