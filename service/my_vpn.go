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
