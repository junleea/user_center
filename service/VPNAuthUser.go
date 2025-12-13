package service

import (
	"encoding/json"
	"log"
	"sync"
	"user_center/dao"
	"user_center/proto"
)

type VPNAuthUserMap struct {
	UserMap map[uint][]proto.VPNAuthUserDPInfo
	mutex   sync.Mutex
}

var GlobalVPNAuthUserMap = VPNAuthUserMap{
	UserMap: make(map[uint][]proto.VPNAuthUserDPInfo),
}

type VPNServerConfigMap struct {
	ServerConfigMap map[string]*proto.DPServerOnlineConfig
	mutex           sync.Mutex
}

var GlobalVPNServerConfigMap = VPNServerConfigMap{
	ServerConfigMap: make(map[string]*proto.DPServerOnlineConfig),
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
		var onlineServerConf proto.DPServerOnlineConfig
		//获取地址池信息
		poolConf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeAddressPool, serverConfig.Tunnel)
		var poolConfig proto.AddressPoolConfig
		err = json.Unmarshal([]byte(poolConf.Value), &poolConfig)
		if err != nil {
			log.Println("[ERROR] decode pool:", poolConf.Attr, " config:", poolConf.Value, ", err:", err.Error())
			continue
		}
		GlobalAddressPoolAllocatorMap.mutex.Lock()
		ipAllocator := GlobalAddressPoolAllocatorMap.PoolMap[poolConf.Attr]
		GlobalAddressPoolAllocatorMap.mutex.Unlock()
		if ipAllocator == nil {
			log.Println("[ERROR] decode pool:", poolConf.Attr, " pool map is not exist")
			continue
		}
		//获取tunnel信息
		tunnelConf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeTunnel, serverConfig.Tunnel)
		var tunnelConfig proto.TunnelConfig
		err = json.Unmarshal([]byte(tunnelConf.Value), &poolConfig)
		if err != nil {
			log.Println("[ERROR] decode pool:", poolConf.Attr, " config:", poolConf.Value, ", err:", err.Error())
			continue
		}
		//设置分配IP
		if tunnelConfig.AutoIPv4 {
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

		GlobalVPNServerConfigMap.mutex.Lock()
		GlobalVPNServerConfigMap.ServerConfigMap[serverConfig.ServerID] = &onlineServerConf
		GlobalVPNServerConfigMap.mutex.Unlock()
	}

	return nil
}
