package service

import (
	"encoding/json"
	"errors"
	"log"
	"user_center/dao"
	"user_center/proto"
)

func RegisterMyVPNServerConfigService(user *dao.User, req *proto.SetServerConfigRequest) (code int, err error) {
	if user.Role != proto.USER_IS_ADMIN {
		code = proto.PermissionDenied
		err = errors.New("permission denied")
		return code, err
	}
	conf := dao.GetMyVPNServerConfigByAttr(proto.VPNServerConfigTypeServer, req.ServerID)
	if conf.ID != 0 {
		return proto.MyVPNServerExist, errors.New("vpn server config already exists")
	}
	var configStr string
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
		if serverConf[conf].Type == proto.VPNServerConfigTypeServer {
			err = json.Unmarshal([]byte(serverConf[conf].Value), &serverConfig)
			if err != nil {
				log.Println("[ERROR] GetMyVPNServerConfigService:", err)
				continue
			}
			res = append(res, serverConfig)
		}
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
	err = dao.DeleteMyVPNServerConfigByType(proto.VPNServerConfigTypeTunnel, req.TunnelName)
	if err != nil {
		log.Println("[ERROR] DeleteMyVPNTunnelService:", err)
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	return nil
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

	if err != nil {
		log.Println("[ERROR] SetMyVPNAddressPoolService:", err)
		resp.Code = proto.OperationFailed
		return nil
	}
	resp.Code = proto.SuccessCode
	resp.Message = "success"
	return nil
}
