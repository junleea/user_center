package service

import (
	"encoding/json"
	"log"
	"sync"
	"time"
	"user_center/dao"
	"user_center/proto"
)

type VPNAuthUserMap struct {
	UserMap map[uint][]proto.VPNAuthUserDPInfo
	mutex   sync.Mutex
}

type VPNServerAuthUserMap struct {
	ServerUserMap map[string]*VPNAuthUserMap
	mutex         sync.Mutex
}

var GlobalVPNServerAuthUserMap = VPNServerAuthUserMap{
	ServerUserMap: make(map[string]*VPNAuthUserMap),
}

type VPNServerConfigMap struct {
	ServerConfigMap map[string]*proto.DPServerOnlineConfig
	mutex           sync.Mutex
}

var GlobalVPNServerConfigMap = VPNServerConfigMap{
	ServerConfigMap: make(map[string]*proto.DPServerOnlineConfig),
}

func CheckOnlineServerStatus() {
	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()

	now := time.Now().Unix()
	for k, v := range GlobalVPNServerConfigMap.ServerConfigMap {
		t := now - v.LastServerCheck
		if t > proto.VPNDPServerMaxCheckTime && v.Status == proto.VPNDPServerOnlineStatus {
			v.Status = proto.VPNDPServerOfflineStatus
			log.Println("[INFO] server id:", k, ", has more  than:", t, ", max:", proto.VPNDPServerMaxCheckTime)
		}
	}
}

func CheckOnlineAuthUser() {
	//检查在线auth user, 超过检查时间删除
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()

	now := time.Now().Unix()

	for _, userMap := range GlobalVPNServerAuthUserMap.ServerUserMap {
		//查看服务器配置
		userMap.mutex.Lock()
		for userID, theUserList := range userMap.UserMap {
			var endList []proto.VPNAuthUserDPInfo
			for _, v := range theUserList {
				t := now - v.LastUpdateTime
				if t < proto.VPNAuthUserMaxCheckTime {
					endList = append(endList, v)
					continue
				}
				log.Println("[INFO] user id:", userID, ", session id:", v.UUID, ", more than:", t, ", max:", proto.VPNAuthUserMaxCheckTime)
			}
			userMap.UserMap[userID] = endList
		}
		userMap.mutex.Unlock()
	}
}

func GetVPNServerOnlineList(user *dao.User, resp *proto.GenerateResp) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "无权限"
		return
	}
	var res []proto.DPServerOnlineConfig

	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()

	for _, onlineConfig := range GlobalVPNServerConfigMap.ServerConfigMap {
		res = append(res, *onlineConfig)
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
}

func UpdateServerConfigToOnlineInfo(serverConfig proto.ServerConfig) (err error) {
	var onlineServerConf proto.DPServerOnlineConfig
	//获取地址池信息
	poolConf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeAddressPool, serverConfig.IPv4AddressPool)
	var poolConfig proto.AddressPoolConfig
	err = json.Unmarshal([]byte(poolConf.Value), &poolConfig)
	if err != nil {
		log.Println("[ERROR] decode pool:", poolConf.Attr, " config:", poolConf.Value, ", err:", err.Error())
		return nil
	}
	GlobalAddressPoolAllocatorMap.mutex.Lock()
	defer GlobalAddressPoolAllocatorMap.mutex.Unlock()
	ipAllocator := GlobalAddressPoolAllocatorMap.PoolMap[poolConf.Attr]

	if ipAllocator == nil {
		log.Println("[ERROR] decode pool:", poolConf.Attr, " pool map is not exist")
		return nil
	}
	//获取tunnel信息
	tunnelConfig := GetTunnelConfigByName(serverConfig.Tunnel)
	if tunnelConfig == nil {
		log.Println("[ERROR] tunnel is not exist:", serverConfig.Tunnel)
		return nil
	}

	//设置分配IP
	if tunnelConfig.AutoIPv4 == true {
		ipv4, ipv6, err2 := ipAllocator.AllocateIP(0, &poolConfig.IPv4AddressPool, &poolConfig.IPv6AddressPool)
		if err2 != nil {
			log.Println("[ERROR] allocate ip err:", err2)
		} else {
			if ipv4 != nil {
				onlineServerConf.IPv4Address = ipv4.String()
			}
			if ipv6 != nil {
				onlineServerConf.IPv6Address = ipv6.String()
			}
		}
	} else {
		//添加静态地址
		ipAllocator.AddUseIPByStr(tunnelConfig.IPv4Address, tunnelConfig.IPv6Address)
		onlineServerConf.IPv6Address = tunnelConfig.IPv6Address
		onlineServerConf.IPv4Address = tunnelConfig.IPv4Address
	}

	onlineServerConf.UserMaxDevice = serverConfig.UserMaxDevice
	onlineServerConf.ServerIP = serverConfig.ServerIP
	onlineServerConf.ServerID = serverConfig.ServerID
	onlineServerConf.DNSServer = serverConfig.DNSServer
	onlineServerConf.IPType = serverConfig.IPType
	onlineServerConf.Name = serverConfig.Name
	onlineServerConf.IPv6Router = serverConfig.IPv6Router
	onlineServerConf.IPv4Router = serverConfig.IPv4Router
	onlineServerConf.AllowUserID = serverConfig.AllowUserID
	onlineServerConf.DurationTime = serverConfig.DurationTime
	onlineServerConf.Encryption = serverConfig.Encryption
	onlineServerConf.Protocol = serverConfig.Protocol
	onlineServerConf.UDPPort = serverConfig.UDPPort
	onlineServerConf.TCPPort = serverConfig.TCPPort
	onlineServerConf.Hash = serverConfig.Hash
	onlineServerConf.Status = proto.VPNDPServerInitStatus
	onlineServerConf.IPv4MTU = tunnelConfig.IPv4MTU
	onlineServerConf.IPv6MTU = tunnelConfig.IPv6MTU
	onlineServerConf.UploadLimit = tunnelConfig.UploadLimit
	onlineServerConf.DownloadLimit = tunnelConfig.DownloadLimit
	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	GlobalVPNServerConfigMap.ServerConfigMap[serverConfig.ServerID] = &onlineServerConf
	log.Println("[INFO] vpn online info set server:", serverConfig.ServerID)

	return nil
}

func InitVPNDPServerConfig() (err error) {
	//查找所有server
	servers := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeServer)
	for _, server := range servers {
		var serverConfig proto.ServerConfig
		err = json.Unmarshal([]byte(server.Value), &serverConfig)
		if err != nil {
			log.Println("[ERROR] decode server:", server.Attr, " config:", server.Value, ", err:", err.Error())
			continue
		}
		err = UpdateServerConfigToOnlineInfo(serverConfig)
		if err != nil {
			continue
		}
	}

	return nil
}

func GetTunnelConfigByName(name string) (res *proto.TunnelConfig) {
	tunnelConf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeTunnel, name)
	log.Println("[INFO] tunnel config:", tunnelConf.Value)
	if tunnelConf.ID > 0 {
		res = new(proto.TunnelConfig)
		err := json.Unmarshal([]byte(tunnelConf.Value), res)
		if err != nil {
			log.Println("[ERROR] get tunnel config:", name, ", err:", err)
		}
	}
	return res
}

func GetTunnelConfigList() (res []proto.TunnelConfig) {
	tunnelConf := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeTunnel)
	var err error
	for _, tunnel := range tunnelConf {
		if tunnel.ID > 0 {
			var tunnelConfig proto.TunnelConfig
			err = json.Unmarshal([]byte(tunnel.Value), &tunnelConfig)
			if err != nil {
				log.Println("[ERROR] get tunnel config:", tunnel.Attr, ", err:", err)
			} else {
				res = append(res, tunnelConfig)
			}
		}
	}
	return res
}

func GetAddressPoolByName(name string) (res *proto.AddressPoolConfig) {
	poolConf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeAddressPool, name)
	if poolConf.ID > 0 {
		res = new(proto.AddressPoolConfig)
		err := json.Unmarshal([]byte(poolConf.Value), res)
		if err != nil {
			log.Println("[ERROR] get address pool config:", name, ", err:", err)
		}
	}
	return res
}

func GetAddressPoolConfigList() (res []proto.AddressPoolConfig) {
	poolConf := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeAddressPool)
	var err error
	for _, tunnel := range poolConf {
		if tunnel.ID > 0 {
			var poolConfig proto.AddressPoolConfig
			err = json.Unmarshal([]byte(tunnel.Value), &poolConfig)
			if err != nil {
				log.Println("[ERROR] get tunnel config:", tunnel.Attr, ", err:", err)
			} else {
				res = append(res, poolConfig)
			}
		}
	}
	return res
}
