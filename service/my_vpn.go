package service

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker"
	"github.com/gin-gonic/gin"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type VPNSecretID struct {
	id    uint
	mutex sync.Mutex
}

func (vs *VPNSecretID) GetID() uint {
	var id uint
	vs.mutex.Lock()
	id = vs.id
	vs.id += worker.SecureRandomInt(128)
	log.Println("secret id(next):", vs.id)
	vs.mutex.Unlock()
	return id
}

func (vs *VPNSecretID) SetID(id uint) {
	vs.mutex.Lock()
	vs.id = id
	vs.mutex.Unlock()
}

var MyVPNSecretID VPNSecretID

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
	restart := false
	configByte, err := json.Marshal(req.Config)
	if err != nil {
		log.Println("[ERROR] SetMyVPNServerConfigService marshal:", err)
		code = proto.OperationFailed
		err = errors.New("marshal vpn server config failed")
		return code, err
	}
	originalConf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeServer, req.ServerID)
	var originalConfig proto.ServerConfig
	err = json.Unmarshal([]byte(originalConf.Value), &originalConfig)
	if err != nil {
		log.Println("[ERROR] SetMyVPNServerConfigService unmarshal:", err)
		code = proto.OperationFailed
		err = errors.New("unmarshal vpn server config failed")
		return code, err
	}
	if originalConfig.IPv4AddressPool != req.Config.IPv4AddressPool || originalConfig.IPv6AddressPool != req.Config.IPv6AddressPool || 
	  	originalConfig.Protocol != req.Config.Protocol || originalConfig.UDPPort != req.Config.UDPPort || originalConfig.TCPPort != req.Config.TCPPort ||
		originalConfig.Encryption != req.Config.Encryption {
		restart = true
	}
	configStr = string(configByte)
	err = dao.UpdateMyVPNServerConfigByTypeAttr(proto.VPNServerConfigTypeServer, req.ServerID, configStr)
	if err != nil {
		log.Println("[ERROR] SetMyVPNServerConfigService:", err)
		code = proto.OperationFailed
		err = errors.New("update store vpn server config failed")
		return code, err
	}
	err = UpdateServerConfigToOnlineInfo(req.Config)
	if err != nil {
		log.Println("[ERROR] SetMyVPNServerConfigService online:", err)
		code = proto.OperationFailed
		err = errors.New("update vpn server config  online failed")
		return code, err
	}
	if restart == true {
		// send dp server message to restart
		SendToDPServerRestartVPNServer(req.ServerID)

		//kickout all user
		KickoutAllVPNUser(req.ServerID)
	}
	return proto.SuccessCode, nil
}

func OptionDPServerService(server_id string, option string, resp *proto.GenerateResp) {
	switch option {
	case "restart":
		SendToDPServerRestartVPNServer(server_id)
	case "update":
		SendToDPServerUpdateVPNServer(server_id)
	default:
		resp.Code = proto.ParameterError
		resp.Message = "invalid option"
		return
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
}

func SendToDPServerUpdateVPNServer(serverID string) {
	var event proto.VPNDPServerEvent
	event.MsgType = proto.DPMsgServerControlType
	event.OpCode = proto.DPOpCodeServerUpdate
	//加入消息队列
	key := "vpn_dp_event_" + serverID

	msg, err := json.Marshal(&event)

	if err != nil {
		log.Println("server id:", serverID, " event to dp server update encode err:", err)
		return
	}

	worker.Publish(key, string(msg), time.Second*10)
}
func SendToDPServerRestartVPNServer(serverID string) {
	var event proto.VPNDPServerEvent
	event.MsgType = proto.DPMsgServerControlType
	event.OpCode = proto.DPOpCodeRestart
	//加入消息队列
	key := "vpn_dp_event_" + serverID

	msg, err := json.Marshal(&event)

	if err != nil {
		log.Println("server id:", serverID, " event to dp server restart encode err:", err)
		return
	}

	worker.Publish(key, string(msg), time.Second*10)
}

func KickoutAllVPNUser(serverID string) {
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()
	count := 0
	authUserMap, exist := GlobalVPNServerAuthUserMap.ServerUserMap[serverID]
	if exist == false {
		return
	}
	serverConfig := GetServerConfigByServerID(serverID)
	authUserMap.mutex.Lock()
	defer authUserMap.mutex.Unlock()

	// 踢出所有用户
	for _, user_ := range authUserMap.AuthUserMap {
		count++
		//释放IP
		GlobalAddressPoolAllocatorMap.mutex.Lock()
		ipa := GlobalAddressPoolAllocatorMap.PoolMap[serverConfig.IPv4AddressPool]
		ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv4).To4())
		ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv6).To16())
		GlobalAddressPoolAllocatorMap.mutex.Unlock()
		SendVPNAuthUserMsgToClient(proto.VPNClientOpCodeKickOut, serverID, &user_)

		//add admin kick out event
		var eventLog proto.MyVPNUserLoginInfo
		eventLog.UserID = user_.UserID
		eventLog.UserName = user_.UserName
		eventLog.ServerID = serverID
		eventLog.PrivateIP = user_.PrivateIPv4
		if user_.HostInfo != nil {
			eventLog.HostID = user_.HostInfo.HostID
		}
		eventLog.SessionID = user_.UUID
		eventLog.Event = proto.VPNAdminKickOutEvent

		dao.CreateMyVPNUserLoginInfo(&eventLog)
	}
	log.Println("kickout all user count:", count)
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
	//删除在线服务器信息
	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	delete(GlobalVPNServerConfigMap.ServerConfigMap, req.ServerID)
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
		// 直接通过uuid查找用户
		if authUser, ok := authUserMap.AuthUserMap[req.UUID]; ok {
			authUser.LastUpdateTime = time.Now().Unix()
			authUserMap.AuthUserMap[req.UUID] = authUser
			exist = true
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
		// 按用户ID分组
		userGroups := make(map[uint][]proto.VPNAuthUserDPInfo)
		for _, authUser := range authUserMap.AuthUserMap {
			userGroups[authUser.UserID] = append(userGroups[authUser.UserID], authUser)
		}
		// 组装返回数据
		for userID, authUsers := range userGroups {
			var authUser proto.VPNAuthUserDPInfoList
			authUser.UserID = userID
			authUser.AuthUser = authUsers
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
		for _, allowUser := range serverConfig.AllowUser {
			if allowUser.UserID == user.ID {
				var supportServer proto.SupportVPNServer
				supportServer.ServerID = server.Attr
				supportServer.ServerIP = serverConfig.ServerIP
				supportServer.ServerInfo = serverConfig.ServerInfo
				supportServer.ServerIPV6 = serverConfig.ServerIPV6
				supportServer.Name = serverConfig.Name
				supportServer.Protocol = serverConfig.Protocol
				supportServer.UDPPort = serverConfig.UDPPort
				supportServer.TCPPort = serverConfig.TCPPort
				res = append(res, supportServer)
			}
		}
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
	return nil
}

// filterUserRoutes 筛选用户的路由：全局路由 + 用户路由 + 用户所属用户组的路由
func filterUserRoutes(userID uint, routes []proto.VPNRouter) []proto.VPNRouter {
	var filteredRoutes []proto.VPNRouter

	// 获取用户信息，包括所属用户组
	userInfo := dao.FindUserByID2(int(userID))

	for _, route := range routes {
		// 全局路由：所有用户都有
		if route.RouterType == proto.VPNRouterTypeGlobal {
			filteredRoutes = append(filteredRoutes, route)
			continue
		}

		// 用户路由：TargetID 等于当前用户ID
		if route.RouterType == proto.VPNRouterTypeUser && route.TargetID == int(userID) {
			filteredRoutes = append(filteredRoutes, route)
			continue
		}

		// 用户组路由：TargetID 等于用户所属的用户组ID
		if route.RouterType == proto.VPNRouterTypeGroup && route.TargetID == userInfo.Prev {
			filteredRoutes = append(filteredRoutes, route)
			continue
		}
	}

	return filteredRoutes
}

// prepare vpn client online, 快速重连时使用原有的配置和IP地址
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

	// 筛选用户的路由：全局路由 + 用户路由 + 用户所属用户组的路由
	res.IPv4Router = filterUserRoutes(user.ID, serverConf.IPv4Router)
	res.IPv6Router = filterUserRoutes(user.ID, serverConf.IPv6Router)
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

		// 直接通过uuid查找
		if auth, ok := authUserMap.AuthUserMap[uuidStr]; ok {
			// 验证用户ID匹配
			if auth.UserID == user.ID {
				res.PrivateIPv4 = auth.PrivateIPv4
				res.PrivateIPv6 = auth.PrivateIPv6
				res.VPNDPSecret = auth.VPNDPSecret
				res.ID = auth.ID
			}
		}
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
}

func MatchVPNAllowUser(userGroups []proto.UserGroupInfo, allowUsers []proto.VPNAllowUser) (res proto.VPNAllowUser, err error) {
	//获取用户组织架构信息, 用户所属用户组列表

	//遍历用户组织信息架构， 找到允许最精细的配置信息
	for _, ug := range userGroups {
		for _, allowUser := range allowUsers {
			if allowUser.UserID == ug.UserGroupID {
				return allowUser, nil
			}
		}
	}
	//未找到。 查看是否有允许所有用户的配置
	for _, allowUser := range allowUsers {
		if allowUser.UserID == 0 {
			return allowUser, nil
		}
	}
	//未找到任何配置，返回错误，不允许用户连接
	return res, errors.New("user not allowed")
}

// start vpn client online, 分配新的IP地址和配置及加密密钥
func GetClientConfigService(user *dao.User, resp *proto.GenerateResp, serverID string, hostInfo *proto.VPNClientHostInfo, c *gin.Context) (err error) {
	var res proto.GetClientConfigOnlineResponse
	var authUser proto.VPNAuthUserDPInfo

	authUser.UserID = user.ID
	res.UserID = user.ID
	authUser.UserName = user.Name
	authUser.UUID = uuid.New().String()
	authUser.OnlineTime = time.Now().Unix()
	authUser.ClientIP = c.ClientIP()
	if hostInfo == nil || hostInfo.HostID == "" {
		resp.Code = proto.ParameterError
		resp.Message = "host info is empty"
		return nil	
	}
	vpn_info, hostErr := dao.GetVPNHostInfoByHostID(hostInfo.HostID)
	if hostErr != nil && !errors.Is(hostErr, gorm.ErrRecordNotFound) {
		resp.Code = proto.OperationFailed
		resp.Message = "get host info failed"
		log.Println("[ERROR] GetVPNHostInfoByHostID:", hostErr)
		return nil
	}
	if vpn_info == nil {
		//创建
		vpn_info = &proto.VPNHostInfoModel{
			InfoStat:     hostInfo.InfoStat,
			ComputerInfo: hostInfo.ComputerInfo,
		}
	} else {
		vpn_info.ComputerInfo = hostInfo.ComputerInfo
		vpn_info.Platform = hostInfo.Platform
		vpn_info.PlatformFamily = hostInfo.PlatformFamily
		vpn_info.Procs = hostInfo.Procs
	}

	if _, err := dao.UpsertVPNHostInfoByHostID(vpn_info); err != nil {
		resp.Code = proto.OperationFailed
		resp.Message = "save host info failed"
		log.Println("[ERROR] UpsertVPNHostInfoByHostID:", err)
		return nil
	}


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

	//获取组织架构
	userGroupsInfo, err2 := dao.GetUserGroupChain(int(user.ID))
	if err2 != nil {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		log.Println("[ERROR] MatchVPNAllowUser:", err2)
		return nil
	}
	var userGroups []proto.UserGroupInfo
	for _, ug := range userGroupsInfo {
		userGroups = append(userGroups, proto.UserGroupInfo{UserGroupID: ug.ID})
	}
	allowUser, err := MatchVPNAllowUser(userGroups, serverConfig.AllowUser)
	if err != nil {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
			log.Println("user id:", user.ID, " try to connect vpn server:", serverConfig.Name, ", but not in allow users")
		return nil
	}
	authUser.MaxDownload = allowUser.MaxDownload
	authUser.MaxUpload = allowUser.MaxUpload
	authUser.UserGroupInfo = userGroups

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
	res.IPv4Prefix = vpnOnlineServer.IPv4Prefix
	res.IPv6Prefix = vpnOnlineServer.IPv6Prefix
	res.Gateway = vpnOnlineServer.IPv4Address
	//if vpnOnlineServer.Status != proto.VPNDPServerOnlineStatus {
	//	resp.Code = proto.VPNServerStatusError
	//	resp.Message = "VPN服务器状态不可用"
	//	return nil
	//}

	//获取地址池
	poolInfo := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeAddressPool, vpnOnlineServer.IPv6AddressPool)
	var poolConfig proto.AddressPoolConfig
	err = json.Unmarshal([]byte(poolInfo.Value), &poolConfig)

	//客户端配置：筛选用户的路由（全局+用户+用户组）
	res.IPv4Router = filterUserRoutes(user.ID, serverConfig.IPv4Router)
	res.IPv6Router = filterUserRoutes(user.ID, serverConfig.IPv6Router)
	res.ServerID = serverConfig.ServerID
	res.ServerIP = serverConfig.ServerIP
	res.ServerIPV6 = vpnOnlineServer.ServerIPV6
	res.ServerIPType = serverConfig.ServerIPType
	res.UDPPort = serverConfig.UDPPort
	res.TCPPort = serverConfig.TCPPort
	res.Protocol = serverConfig.Protocol
	res.IPType = serverConfig.IPType
	res.DNSServer = serverConfig.DNSServer

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
	ipv4, ipv6, err := ipAllocator.AllocateIP(int(user.ID))
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

	key, keyStr, keyErr := worker.GenerateDPEncryptionKey(serverConfig.Encryption)
	if keyErr != nil {
		log.Println("[ERROR] user:", user.ID, ", uuid:", authUser.UUID, ", generate dp secret key err:", keyErr, ", key:", string(key))
		resp.Code = proto.OperationFailed
		resp.Message = "生成加密密钥失败"
	}
	authUser.VPNDPSecret = keyStr
	authUser.LastUpdateTime = time.Now().Unix()
	res.SessionID = authUser.UUID

	res.VPNDPSecret = authUser.VPNDPSecret
	authUser.ID = MyVPNSecretID.GetID()
	log.Println("[INFO] user:", user.ID, ", name:", user.Name, ", vpn id:", authUser.ID)
	res.ID = authUser.ID
	authUser.HostInfo = hostInfo

	//将auth user 加入map进行管控
	//查找该server的auth user map
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()

	hostInfo_ := proto.VPNClientHostInfo{}
	hostInfo_ = *hostInfo
	authUser.HostInfo = &hostInfo_

	authUserMap := GlobalVPNServerAuthUserMap.ServerUserMap[serverID]
	if authUserMap != nil {
		authUserMap.mutex.Lock()
		defer authUserMap.mutex.Unlock()

		// 检查用户当前在线设备数量
		currentCount := authUserMap.UserCountMap[user.ID]
		if currentCount >= allowUser.MaxConnections && allowUser.MaxConnections != 0{ // 0表示不限制连接数
			resp.Code = proto.VPNServerMaxUserDevice
			resp.Message = "超出用户同时最大连接数限制"
			return
		}

		// 添加到AuthUserMap
		authUserMap.AuthUserMap[authUser.UUID] = authUser
		// 更新用户计数
		authUserMap.UserCountMap[user.ID] = currentCount + 1
	} else {
		// 确保全局 ServerUserMap 已初始化（可能为 nil）
		if GlobalVPNServerAuthUserMap.ServerUserMap == nil {
			GlobalVPNServerAuthUserMap.ServerUserMap = make(map[string]*VPNAuthUserMap)
		}

		// 初始化新的 VPNAuthUserMap，并初始化其内部的两个map
		authUserMap_ := VPNAuthUserMap{
			AuthUserMap:  make(map[string]proto.VPNAuthUserDPInfo),
			UserCountMap: make(map[uint]int),
		}

		// 添加到AuthUserMap
		authUserMap_.AuthUserMap[authUser.UUID] = authUser
		// 设置用户计数
		authUserMap_.UserCountMap[user.ID] = 1

		GlobalVPNServerAuthUserMap.ServerUserMap[serverID] = &authUserMap_
	}

	//add online event
	var eventLog proto.MyVPNUserLoginInfo
	eventLog.UserID = user.ID
	eventLog.UserName = user.Name
	eventLog.ServerID = serverID
	eventLog.PrivateIP = authUser.PrivateIPv4
	eventLog.HostID = hostInfo.HostID
	eventLog.ClientIP = c.ClientIP()
	eventLog.SessionID = authUser.UUID
	eventLog.Event = proto.UserLoginEvent

	eventErr := dao.CreateMyVPNUserLoginInfo(&eventLog)
	if eventErr != nil {
		log.Println("[ERROR] user:", user.ID, ", uuid:", authUser.UUID, ", create my vpn user login info err:", eventErr)
	}

	//update host info
	if vpn_info.ID != 0 {
		dao.UpdateVPNHostInfo(vpn_info.ID, vpn_info)
	}else{
		dao.CreateVPNHostInfo(vpn_info)
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = res
	SendVPNAuthUserMsgToDPServer(proto.DPOpCodeAuthUserAdd, serverID, &authUser)

	return nil
}

func GetDPServerOnlineUsers(serverID string, resp *proto.GenerateResp) {
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()
	authUserMap, exist := GlobalVPNServerAuthUserMap.ServerUserMap[serverID]
	if exist == false {
		resp.Code = proto.SuccessCode
		resp.Message = "no users"
		return
	}
	var respUsers []proto.VPNAuthUserDPInfo
	authUserMap.mutex.Lock()
	defer authUserMap.mutex.Unlock()
	// 直接遍历AuthUserMap获取所有用户
	for _, user := range authUserMap.AuthUserMap {
		respUsers = append(respUsers, user)
	}
	//不返回密钥信息
	for i, _ := range respUsers {
		respUsers[i].VPNDPSecret = ""
	}
	resp.Data = respUsers
	resp.Code = proto.SuccessCode
	resp.Message = "success"
}

func KickOutAllUserService(user *dao.User, serverID string, resp *proto.GenerateResp) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return
	}
	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()
	authUserMap, exist := GlobalVPNServerAuthUserMap.ServerUserMap[serverID]
	if exist == false {
		resp.Code = proto.SuccessCode
		resp.Message = "the server no users"
		return
	}
	count := 0
	serverConfig := GetServerConfigByServerID(serverID)
	authUserMap.mutex.Lock()
	defer authUserMap.mutex.Unlock()

	// 遍历所有auth user释放资源
	for _, user_ := range authUserMap.AuthUserMap {
		count++
		//释放IP
		GlobalAddressPoolAllocatorMap.mutex.Lock()
		ipa := GlobalAddressPoolAllocatorMap.PoolMap[serverConfig.IPv4AddressPool]
		ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv4).To4())
		ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv6).To16())
		GlobalAddressPoolAllocatorMap.mutex.Unlock()
	}
	resp.Data = len(authUserMap.UserCountMap)
	// 重置两个map
	authUserMap.AuthUserMap = make(map[string]proto.VPNAuthUserDPInfo)
	authUserMap.UserCountMap = make(map[uint]int)
	SendVPNAuthUserMsgToDPServer(proto.DPOpCodeAuthUserDelAll, serverID, nil)
	resp.Code = proto.SuccessCode
	resp.Message = "success"
}


func KickOutUserService(req *proto.KickOutUserRequest, user *dao.User, clientIP string, resp *proto.GenerateResp) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "permission denied"
		return
	}

	GlobalVPNServerAuthUserMap.mutex.Lock()
	defer GlobalVPNServerAuthUserMap.mutex.Unlock()
	authUserMap, exist := GlobalVPNServerAuthUserMap.ServerUserMap[req.ServerID]
	if exist == false {
		resp.Code = proto.SuccessCode
		resp.Message = "the server no users"
		return
	}
	count := 0
	serverConfig := GetServerConfigByServerID(req.ServerID)
	authUserMap.mutex.Lock()
	defer authUserMap.mutex.Unlock()

	if req.Type > 0 {
		// 踢出所有用户
		for _, user_ := range authUserMap.AuthUserMap {
			count++
			//释放IP
			GlobalAddressPoolAllocatorMap.mutex.Lock()
			ipa := GlobalAddressPoolAllocatorMap.PoolMap[serverConfig.IPv4AddressPool]
			ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv4).To4())
			ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv6).To16())
			GlobalAddressPoolAllocatorMap.mutex.Unlock()
			SendVPNAuthUserMsgToClient(proto.VPNClientOpCodeKickOut, req.ServerID, &user_)

			//add admin kick out event
			var eventLog proto.MyVPNUserLoginInfo
			eventLog.UserID = user_.UserID
			eventLog.UserName = user_.UserName
			eventLog.ServerID = req.ServerID
			eventLog.PrivateIP = user_.PrivateIPv4
			if user_.HostInfo != nil {
				eventLog.HostID = user_.HostInfo.HostID
			}
			eventLog.ClientIP = clientIP
			eventLog.SessionID = user_.UUID
			eventLog.Event = proto.VPNAdminKickOutEvent

			dao.CreateMyVPNUserLoginInfo(&eventLog)
		}
		resp.Data = len(authUserMap.UserCountMap)
		// 重置两个map
		authUserMap.AuthUserMap = make(map[string]proto.VPNAuthUserDPInfo)
		authUserMap.UserCountMap = make(map[uint]int)
		SendVPNAuthUserMsgToDPServer(proto.DPOpCodeAuthUserDelAll, req.ServerID, nil)
		resp.Code = proto.SuccessCode
		resp.Message = "success"
		return
	}

	var delSessionMap = make(map[string]bool)
	for _, session := range req.Sessions {
		delSessionMap[session.Session] = true
	}

	// 遍历需要删除的session
	for sessionID := range delSessionMap {
		if user_, ok := authUserMap.AuthUserMap[sessionID]; ok {
			count++
			//释放IP
			GlobalAddressPoolAllocatorMap.mutex.Lock()
			ipa := GlobalAddressPoolAllocatorMap.PoolMap[serverConfig.IPv4AddressPool]
			ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv4).To4())
			ipa.ReleaseIP(net.ParseIP(user_.PrivateIPv6).To16())
			GlobalAddressPoolAllocatorMap.mutex.Unlock()
			SendVPNAuthUserMsgToDPServer(proto.DPOpCodeAuthUserDel, req.ServerID, &user_)
			SendVPNAuthUserMsgToClient(proto.VPNClientOpCodeKickOut, req.ServerID, &user_)

			//add admin kick out event
			var eventLog proto.MyVPNUserLoginInfo
			eventLog.UserID = user_.UserID
			eventLog.UserName = user_.UserName
			eventLog.ServerID = req.ServerID
			eventLog.PrivateIP = user_.PrivateIPv4
			if user_.HostInfo != nil {
				eventLog.HostID = user_.HostInfo.HostID
			}
			eventLog.ClientIP = clientIP
			eventLog.SessionID = user_.UUID
			eventLog.Event = proto.VPNAdminKickOutEvent
			if user_.UserID > 0 {
				dao.CreateMyVPNUserLoginInfo(&eventLog)
			}
			
			// 从map中删除
			delete(authUserMap.AuthUserMap, sessionID)

			// 更新用户计数
			userID := user_.UserID
			currentCount := authUserMap.UserCountMap[userID]
			if currentCount > 1 {
				authUserMap.UserCountMap[userID] = currentCount - 1
			} else {
				delete(authUserMap.UserCountMap, userID)
			}
		}
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = count

}

func HandleReceiveDPServerDataInfoService(req *proto.VPNDPServerEvent, user *dao.User, serverID string) {
	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	server, ok := GlobalVPNServerConfigMap.ServerConfigMap[serverID]
	if ok == false || server == nil {
		log.Println("[ERROR] server not found:", serverID)
		return
	}

	if req.DPServerStatus == nil {
		log.Println("[ERROR] server has no DPServerStatus")
		return
	}
	server.VPNStatus = req.DPServerStatus.GetInfo()
	log.Println("[INFO] receive dp server msg op code:", req.OpCode, " update status success!")
}

func HandleReceiveDPServerInfoService(req *proto.VPNDPServerEvent, user *dao.User, serverID string) {
	GlobalVPNServerConfigMap.mutex.Lock()
	defer GlobalVPNServerConfigMap.mutex.Unlock()
	server, ok := GlobalVPNServerConfigMap.ServerConfigMap[serverID]
	if ok == false || server == nil {
		log.Println("[ERROR] server not found:", serverID)
		return
	}

	if req.DPServerInfo == nil {
		log.Println("[ERROR] server has no DPServerInfo")
		return
	}
	server.DPServerInfo = *req.DPServerInfo
	log.Println("[INFO] receive dp server msg op code:", req.OpCode, " update status success!")
}

// VPNLogResponse VPN日志响应结构
type VPNLogResponse struct {
	Total    int64                      `json:"total"`
	List     []proto.MyVPNUserLoginInfo `json:"list"`
	Page     int                        `json:"page"`
	PageSize int                        `json:"page_size"`
}

func GetVPNLogsService(page, pageSize, userID, serverID, eventType, startTime, endTime string, resp *proto.GenerateResp) error {
	pageInt, _ := strconv.Atoi(page)
	pageSizeInt, _ := strconv.Atoi(pageSize)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 || pageSizeInt > 100 {
		pageSizeInt = 20
	}

	offset := (pageInt - 1) * pageSizeInt

	db := dao.DB.Model(&proto.MyVPNUserLoginInfo{}).Order("created_at desc")

	if userID != "" {
		uid, _ := strconv.Atoi(userID)
		if uid > 0 {
			db = db.Where("user_id = ?", uid)
		}
	}
	if serverID != "" {
		db = db.Where("server_id = ?", serverID)
	}
	if eventType != "" {
		et, _ := strconv.Atoi(eventType)
		if et > 0 {
			db = db.Where("event = ?", et)
		}
	}
	if startTime != "" {
		st, _ := strconv.ParseInt(startTime, 10, 64)
		if st > 0 {
			db = db.Where("created_at >= ?", time.Unix(st, 0))
		}
	}
	if endTime != "" {
		et, _ := strconv.ParseInt(endTime, 10, 64)
		if et > 0 {
			db = db.Where("created_at <= ?", time.Unix(et, 0))
		}
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return err
	}

	var infos []proto.MyVPNUserLoginInfo
	if err := db.Offset(offset).Limit(pageSizeInt).Find(&infos).Error; err != nil {
		return err
	}

	respData := VPNLogResponse{
		Total:    total,
		List:     infos,
		Page:     pageInt,
		PageSize: pageSizeInt,
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = respData
	return nil
}

func GetVPNHostInfoService(user *dao.User, hostID, page, pageSize string, resp *proto.GenerateResp) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Code = proto.PermissionDenied
		resp.Message = "无权限"
		return
	}

	// 按host_id精确查询
	if hostID != "" {
		info, err := dao.GetVPNHostInfoByHostID(hostID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				resp.Code = proto.SuccessCode
				resp.Message = "success"
				resp.Data = nil
				return
			}
			log.Println("[ERROR] GetVPNHostInfoService:", err)
			resp.Code = proto.OperationFailed
			resp.Message = "获取主机信息失败"
			return
		}
		resp.Code = proto.SuccessCode
		resp.Message = "success"
		resp.Data = info
		return
	}

	// 分页查询全部
	pageInt, _ := strconv.Atoi(page)
	pageSizeInt, _ := strconv.Atoi(pageSize)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 || pageSizeInt > 100 {
		pageSizeInt = 20
	}

	infos, total, err := dao.ListVPNHostInfo(pageInt, pageSizeInt)
	if err != nil {
		log.Println("[ERROR] GetVPNHostInfoService list:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "获取主机信息失败"
		return
	}

	resp.Code = proto.SuccessCode
	resp.Message = "success"
	resp.Data = proto.VPNHostInfoListResponse{
		Total:    total,
		List:     infos,
		Page:     pageInt,
		PageSize: pageSizeInt,
	}
}