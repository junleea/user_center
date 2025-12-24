package service

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"log"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker"
)

func RegisterMyVPNServerConfigService(user *dao.User, req *proto.SetServerConfigRequest) (code int, err error) {
	if user.Role != proto.USER_IS_ADMIN && user.Role != proto.ROLE_VPN_SERVER {
		code = proto.PermissionDenied
		err = errors.New("permission denied")
		return code, err
	}
	conf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeServer, req.ServerID)
	if conf.ID != 0 {
		return proto.MyVPNServerExist, errors.New("vpn server config already exists")
	}
	var configStr string
	req.Config.ServerID = req.ServerID
	if len(req.ServerID) > 10 {
		req.Config.Name = req.ServerID[:10]
	} else {
		req.Config.Name = req.ServerID
	}
	configByte, _ := json.Marshal(req.Config)
	configStr = string(configByte)
	err = dao.CreateMyVPNServerConfig(proto.VPNServerConfigTypeServer, req.ServerID, configStr)
	if err != nil {
		log.Println("[ERROR] RegisterMyVPNServerConfigService:", err)
		code = proto.OperationFailed
		err = errors.New("create vpn server config failed")
		return code, err
	}
	return proto.SuccessCode, nil

}

func SetMyVPNServerConfigService(user *dao.User, req *proto.SetServerConfigRequest) (code int, err error) {
	if user.Role != proto.USER_IS_ADMIN {
		return proto.PermissionDenied, errors.New("permission denied")
	}
	var configStr string
	configByte, _ := json.Marshal(req.Config)
	configStr = string(configByte)
	err = dao.UpdateMyVPNServerConfigByTypeAttr(proto.VPNServerConfigTypeServer, req.ServerID, configStr)
	err = UpdateServerConfigToOnlineInfo(req.Config)
	if err != nil {
		log.Println("[ERROR] SetMyVPNServerConfigService:", err)
		code = proto.OperationFailed
		err = errors.New("update vpn server config failed")
		return code, err
	}
	return proto.SuccessCode, nil
}

func GetMyVPNServerConfigService(user *dao.User) (code int, res []proto.ServerConfig, err error) {
	if user.Role != proto.USER_IS_ADMIN {
		return proto.PermissionDenied, res, errors.New("permission denied")
	}
	serverConf, err := dao.GetMyVPNServerConfig()
	for conf, _ := range serverConf {
		var serverConfig proto.ServerConfig
		err = json.Unmarshal([]byte(serverConf[conf].Value), &serverConfig)
		if err != nil {
			log.Println("[ERROR] GetMyVPNServerConfigService:", err)
			continue
		}
		res = append(res, serverConfig)
	}
	return proto.SuccessCode, res, nil
}

func DeleteMyVPNServerConfigService(user *dao.User, req *proto.SetServerConfigRequest) (code int, err error) {
	if user.Role != proto.USER_IS_ADMIN {
		code = proto.PermissionDenied
		err = errors.New("permission denied")
		return code, err
	}
	err = dao.DeleteMyVPNServerConfigByType(proto.VPNServerConfigTypeServer, req.ServerID)
	if err != nil {
		log.Println("[ERROR] DeleteMyVPNServerConfigService:", err)
		code = proto.OperationFailed
		err = errors.New("delete vpn server config failed")
		return code, err
	}
	return proto.SuccessCode, nil
}

func GetMyVPNAddressPoolService(user *dao.User, resp *proto.GenerateResp) error {
	//权限
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return nil
	}
	var res []proto.AddressPoolRequest //请求响应一致
	serverConf := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeAddressPool)
	var addressPoolConfig proto.AddressPoolConfig
	for _, conf := range serverConf {
		err := json.Unmarshal([]byte(conf.Value), &addressPoolConfig)
		if err != nil {
			log.Println("[ERROR] decode vpn address pool err:", err)
			continue
		}
		var data proto.AddressPoolRequest
		data.PoolName = conf.Attr
		data.Config = addressPoolConfig
		res = append(res, data)
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
	return nil
}

func DeleteMyVPNAddressPoolService(user *dao.User, req *proto.AddressPoolRequest, resp *proto.GenerateResp) (err error) {
	//权限
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return nil
	}
	//获取所有服务器
	server := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeServer)
	//查看地址池是否被使用
	for _, conf := range server {
		var serverConfig proto.ServerConfig
		err2 := json.Unmarshal([]byte(conf.Value), &serverConfig)
		if err2 != nil {
			log.Println("[ERROR] DeleteMyVPNAddressPoolService:", err2)
			continue
		}
		if serverConfig.IPv4AddressPool == req.PoolName || serverConfig.IPv6AddressPool == req.PoolName {
			resp.Code = proto.OperationFailed
			resp.Message = "address pool is in use by vpn server: " + serverConfig.Name
			return nil
		}
	}
	err = dao.DeleteMyVPNServerConfigByType(proto.VPNServerConfigTypeAddressPool, req.PoolName)
	if err != nil {
		log.Println("[ERROR] DeleteMyVPNAddressPoolService:", err)
		resp.Code = proto.OperationFailed
		return nil
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	return nil
}

func GetMyVPNTunnelService(user *dao.User, resp *proto.GenerateResp) error {
	//权限
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return nil
	}
	var res []proto.TunnelRequestAndResponse
	serverConf := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeTunnel)
	var tunnelConfig proto.TunnelConfig
	for _, conf := range serverConf {
		err := json.Unmarshal([]byte(conf.Value), &tunnelConfig)
		if err != nil {
			log.Println("[ERROR] decode vpn tunnel err:", err)
			continue
		}
		var data proto.TunnelRequestAndResponse
		data.TunnelName = conf.Attr
		data.Config = tunnelConfig
		res = append(res, data)
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
	return nil
}

func DeleteMyVPNTunnelService(user *dao.User, req *proto.TunnelRequestAndResponse, resp *proto.GenerateResp) (err error) {
	//权限
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return nil
	}

	//获取所有服务器
	server := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeServer)
	//查看地址池是否被使用
	for _, conf := range server {
		var serverConfig proto.ServerConfig
		err2 := json.Unmarshal([]byte(conf.Value), &serverConfig)
		if err2 != nil {
			log.Println("[ERROR] DeleteMyVPNAddressPoolService:", err2)
			continue
		}
		if serverConfig.IPv4AddressPool == req.TunnelName || serverConfig.IPv6AddressPool == req.TunnelName {
			resp.Code = proto.OperationFailed
			resp.Message = "tunnel is in use by vpn server: " + serverConfig.Name
			return nil
		}
	}
	err = dao.DeleteMyVPNServerConfigByType(proto.VPNServerConfigTypeTunnel, req.TunnelName)
	if err != nil {
		log.Println("[ERROR] DeleteMyVPNTunnelService:", err)
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	return nil
}

func SetServerStatusService(user *dao.User, req *proto.SetVPNServerStatusReq, resp *proto.GenerateResp) {

	if user.Role != proto.USER_IS_ADMIN && user.Role != proto.ROLE_VPN_SERVER {
		resp.Code = proto.PermissionDenied
		resp.Message = "no permissions"
		return
	}

	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	serverConfig := GlobalVPNServerConfigMap.ServerConfigMap[req.ServerID]
	if serverConfig == nil {
		resp.Code = proto.OperationFailed
		resp.Message = "server id not exist"
		return
	}

	serverConfig.LastServerCheck = time.Now().Unix()
	serverConfig.Status = req.Status

	resp.Code = proto.SuccessCode
	resp.Message = "success"
}

func SetClientStatusService(user *dao.User, req *proto.SetVPNClientStatusReq, resp *proto.GenerateResp) {
	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	if GlobalVPNServerConfigMap.ServerConfigMap[req.ServerID] == nil {
		resp.Code = proto.OperationFailed
		resp.Message = "server id not exist"
		return
	}
	//查找该server的auth user map
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()

	authUserMap := GlobalVPNServerAuthUserMap.ServerUserMap[req.ServerID]
	exist := false
	if authUserMap != nil {
		authUserMap.mutex.Lock()
		defer authUserMap.mutex.Unlock()
		authList := authUserMap.UserMap[user.ID]
		if authList != nil {
			for i, _ := range authList {
				authList[i].LastUpdateTime = time.Now().Unix()
				exist = true
			}
		}
	}
	if exist {
		resp.Code = proto.SuccessCode
		resp.Message = "success"
	} else {
		resp.Code = proto.OperationFailed
		resp.Message = "the client session is not exist"
	}

}

func SetMyVPNTunnelService(user *dao.User, req *proto.TunnelRequestAndResponse, resp *proto.GenerateResp) error {
	//权限
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return nil
	}
	//查看是否有同名
	existingTunnel := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeTunnel, req.TunnelName)
	var configStr string
	configByte, _ := json.Marshal(req.Config)
	configStr = string(configByte)
	var err error
	if existingTunnel.ID != 0 {
		//更新
		err = dao.UpdateMyVPNServerConfigByTypeAttr(proto.VPNServerConfigTypeTunnel, req.TunnelName, configStr)
	} else {
		//创建
		err = dao.CreateMyVPNServerConfig(proto.VPNServerConfigTypeTunnel, req.TunnelName, configStr)
	}

	if err != nil {
		log.Println("[ERROR] SetMyVPNTunnelService:", err)
		resp.Code = proto.OperationFailed
		return nil
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	return nil
}

func GetVPNOnlineServerConfigWithAuthUser(user *dao.User, resp *proto.GenerateResp, serverID string) {
	//权限
	if user.Role != proto.USER_IS_ADMIN && user.Role != proto.ROLE_VPN_SERVER {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return
	}
	var res proto.GetOnlineServerWithAuthUser

	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	if GlobalVPNServerConfigMap.ServerConfigMap[serverID] == nil {
		resp.Code = proto.OperationFailed
		resp.Message = "server id not exist"
		return
	}
	res.ServerConfig = *GlobalVPNServerConfigMap.ServerConfigMap[serverID]

	//查找该server的auth user map
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()

	authUserMap := GlobalVPNServerAuthUserMap.ServerUserMap[serverID]
	if authUserMap != nil {
		authUserMap.mutex.Lock()
		defer authUserMap.mutex.Unlock()
		for userID, v := range authUserMap.UserMap {
			var authUser proto.VPNAuthUserDPInfoList
			authUser.UserID = userID
			for _, v1 := range v {
				authUser.AuthUser = append(authUser.AuthUser, v1)
			}
			res.AuthUser = append(res.AuthUser, authUser)
		}
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
}

func SetMyVPNAddressPoolService(user *dao.User, req *proto.AddressPoolRequest, resp *proto.GenerateResp) error {
	//权限
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return nil
	}
	//查看是否有同名
	existingPool := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeAddressPool, req.PoolName)
	var configStr string
	configByte, _ := json.Marshal(req.Config)
	configStr = string(configByte)
	var err error
	if existingPool.ID != 0 {
		//更新
		err = dao.UpdateMyVPNServerConfigByTypeAttr(proto.VPNServerConfigTypeAddressPool, req.PoolName, configStr)
	} else {
		//创建
		err = dao.CreateMyVPNServerConfig(proto.VPNServerConfigTypeAddressPool, req.PoolName, configStr)
	}

	err = UpdateIPAddressPoolToMap(req.PoolName, req.Config)

	if err != nil {
		log.Println("[ERROR] SetMyVPNAddressPoolService:", err)
		resp.Code = proto.OperationFailed
		return nil
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	return nil
}

func GetSupportVPNServerList(user *dao.User, resp *proto.GenerateResp) error {

	var res []proto.SupportVPNServer
	//获取所有的Server
	servers := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeServer)

	for _, server := range servers {
		var serverConfig proto.ServerConfig
		err := json.Unmarshal([]byte(server.Value), &serverConfig)
		if err != nil {
			log.Println("[ERROR] GetSupportVPNServerList:", err)
			continue
		}
		for _, userID := range serverConfig.AllowUserID {
			if userID.ID == user.ID {
				var supportServer proto.SupportVPNServer
				supportServer.ServerID = server.Attr
				supportServer.ServerIP = serverConfig.ServerIP
				supportServer.ServerInfo = serverConfig.ServerInfo
				res = append(res, supportServer)
			}
		}
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
	return nil
}

func GetClientConfigExistService(user *dao.User, resp *proto.GenerateResp, serverID, uuidStr string) {
	var res proto.GetClientConfigOnlineResponse

	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	serverConf := GlobalVPNServerConfigMap.ServerConfigMap[serverID]
	if serverConf == nil {
		resp.Code = proto.VPNServerNotExist
		resp.Message = "vpn服务器不存在"
		return
	}

	res.IPv4Router = serverConf.IPv4Router
	res.IPv6Router = serverConf.IPv6Router
	res.IPv4MTU = serverConf.IPv4MTU
	res.IPv6MTU = serverConf.IPv6MTU
	res.Hash = serverConf.Hash
	res.Encryption = serverConf.Encryption
	res.Protocol = serverConf.Protocol
	res.TCPPort = serverConf.TCPPort
	res.UDPPort = serverConf.UDPPort
	res.DownloadLimit = serverConf.DownloadLimit
	res.UploadLimit = serverConf.UploadLimit
	res.ServerID = serverID
	res.ServerIP = serverConf.ServerIP
	res.IPType = serverConf.IPType
	res.ServerIPV6 = serverConf.ServerIPV6
	res.ServerIPType = serverConf.ServerIPType
	res.TunnelIP = serverConf.IPv4Address

	//将auth user 加入map进行管控
	//查找该server的auth user map
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()

	authUserMap := GlobalVPNServerAuthUserMap.ServerUserMap[serverID]
	if authUserMap != nil {
		authUserMap.mutex.Lock()
		defer authUserMap.mutex.Unlock()

		theUserAuthList := authUserMap.UserMap[user.ID]
		if theUserAuthList != nil {
			for _, auth := range theUserAuthList {
				if auth.UUID == uuidStr {
					res.PrivateIPv4 = auth.PrivateIPv4
					res.PrivateIPv6 = auth.PrivateIPv6
					res.VPNDPSecret = auth.VPNDPSecret
				}
			}

		}
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
}

func GetClientConfigService(user *dao.User, resp *proto.GenerateResp, serverID string) (err error) {
	var res proto.GetClientConfigOnlineResponse
	var authUser proto.VPNAuthUserDPInfo
	authUser.UserID = user.ID
	authUser.UserName = user.Name
	authUser.UUID = uuid.New().String()

	server := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeServer, serverID)
	if server.ID == 0 {
		resp.Code = proto.VPNServerNotExist
		resp.Message = "vpn server not exist"
		return nil
	}

	//是否允许该用户
	var serverConfig proto.ServerConfig
	err = json.Unmarshal([]byte(server.Value), &serverConfig)
	if err != nil {
		log.Println("[ERROR] GetClientConfigService:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "decode vpn server config failed"
		return nil
	}
	allowed := false
	for _, userID := range serverConfig.AllowUserID {
		if userID.ID == user.ID {
			allowed = true
			break
		}
	}
	if !allowed {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return nil
	}

	//查看VPN DP服务器状态，在线正常才可
	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	vpnOnlineServer := GlobalVPNServerConfigMap.ServerConfigMap[serverID]
	if vpnOnlineServer == nil {
		resp.Code = proto.VPNServerStatusError
		resp.Message = "VPN服务器未找到在线信息"
		return nil
	}
	res.Encryption = vpnOnlineServer.Encryption
	res.Hash = vpnOnlineServer.Hash
	//if vpnOnlineServer.Status != proto.VPNDPServerOnlineStatus {
	//	resp.Code = proto.VPNServerStatusError
	//	resp.Message = "VPN服务器状态不可用"
	//	return nil
	//}

	//获取地址池
	poolInfo := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeAddressPool, vpnOnlineServer.IPv6AddressPool)
	var poolConfig proto.AddressPoolConfig
	err = json.Unmarshal([]byte(poolInfo.Value), &poolConfig)

	//客户端配置
	res.IPv4Router = serverConfig.IPv4Router
	res.IPv6Router = serverConfig.IPv6Router
	res.ServerID = serverConfig.ServerID
	res.ServerIP = serverConfig.ServerIP
	res.UDPPort = serverConfig.UDPPort
	res.TCPPort = serverConfig.TCPPort
	res.Protocol = serverConfig.Protocol
	res.IPType = serverConfig.IPType

	//获取tunnel
	tunnel := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeTunnel, serverConfig.Tunnel)
	var tunnelConfig proto.TunnelConfig
	err = json.Unmarshal([]byte(tunnel.Value), &tunnelConfig)
	if err != nil {
		log.Println("[ERROR] GetClientConfigService:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "decode vpn tunnel config failed"
		return nil
	}
	/*加入tunnel配置*/
	res.IPv4MTU = tunnelConfig.IPv4MTU
	res.IPv6MTU = tunnelConfig.IPv6MTU
	res.UploadLimit = tunnelConfig.UploadLimit
	res.DownloadLimit = tunnelConfig.DownloadLimit

	//分配客户端IP， 根据ip类型
	//根据地址池分配
	//获取server地址池信息

	GlobalAddressPoolAllocatorMap.mutex.Lock()
	defer GlobalAddressPoolAllocatorMap.mutex.Unlock()
	ipAllocator := GlobalAddressPoolAllocatorMap.PoolMap[serverConfig.IPv4AddressPool]
	if ipAllocator == nil {
		resp.Code = proto.VPNAddressPoolNotExist
		resp.Message = "vpn address pool not exist"
		return nil
	}
	ipv4, ipv6, err := ipAllocator.AllocateIP(user.ID, &poolConfig.IPv4AddressPool, &poolConfig.IPv6AddressPool)
	res.IPType = serverConfig.IPType
	if ipv4 == nil {
		resp.Code = proto.VPNNoAvailableIP
		resp.Message = "no available ipv4"
		return nil
	} else {
		res.PrivateIPv4 = ipv4.String()
		authUser.PrivateIPv4 = ipv4.String()
	}
	//unsupported ipv6 now
	if ipv6 != nil {
		res.PrivateIPv6 = ipv6.String()
		authUser.PrivateIPv6 = ipv6.String()
	}
	authUser.UUID = uuid.NewString()

	key, keyStr, keyErr := worker.Generate32ByteKey()
	if keyErr != nil {
		log.Println("[ERROR] user:", user.ID, ", uuid:", authUser.UUID, ", generate dp secret key err:", keyErr, ", key:", string(key))
		resp.Code = proto.OperationFailed
		resp.Message = "生成加密密钥失败"
	}
	authUser.VPNDPSecret = keyStr
	authUser.LastUpdateTime = time.Now().Unix()
	res.SessionID = authUser.UUID

	res.VPNDPSecret = authUser.VPNDPSecret

	//将auth user 加入map进行管控
	//查找该server的auth user map
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()

	authUserMap := GlobalVPNServerAuthUserMap.ServerUserMap[serverID]
	if authUserMap != nil {
		authUserMap.mutex.Lock()
		defer authUserMap.mutex.Unlock()

		theUserAuthList := authUserMap.UserMap[user.ID]
		if theUserAuthList == nil {
			theUserList := make([]proto.VPNAuthUserDPInfo, 2)
			theUserList = append(theUserList, authUser)
			authUserMap.UserMap[user.ID] = theUserList
		} else {
			if len(theUserAuthList) >= vpnOnlineServer.UserMaxDevice {
				resp.Code = proto.VPNServerMaxUserDevice
				resp.Message = "超出用户最大登录设备限制"
				return
			}
			theUserAuthList = append(theUserAuthList, authUser)
			authUserMap.UserMap[user.ID] = theUserAuthList
		}
	} else {
		// 确保全局 ServerUserMap 已初始化（可能为 nil）
		if GlobalVPNServerAuthUserMap.ServerUserMap == nil {
			GlobalVPNServerAuthUserMap.ServerUserMap = make(map[string]*VPNAuthUserMap)
		}

		// 初始化新的 VPNAuthUserMap，并初始化其内部的 UserMap
		authUserMap_ := VPNAuthUserMap{
			UserMap: make(map[uint][]proto.VPNAuthUserDPInfo),
		}

		// 直接赋值单元素切片
		authUserMap_.UserMap[user.ID] = []proto.VPNAuthUserDPInfo{authUser}

		GlobalVPNServerAuthUserMap.ServerUserMap[serverID] = &authUserMap_
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res

	return nil
}
