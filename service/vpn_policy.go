package service

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker"
)

func GetMyVPNPolicyByServerID(user *dao.User, resp *proto.GenerateResp, serverID string) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Message = "no permission"
		resp.Code = proto.PermissionDenied
	} else {
		policies, err := dao.GetVPNPolicyByServerID(serverID)
		if err != nil {
			log.Println("[ERROR] request id:", resp.RequestID, " user:", user.ID, " get vpn policy dao err:", err)
		} else {
			resp.Data = policies
		}
		resp.Code = proto.SuccessCode
		resp.Message = "success"
	}
}

func CheckVPNPolicyUpdateParam(resp *proto.GenerateResp, req *proto.VPNPolicyRequest) error {
	if req.ServerID == "" {
		return errors.New("server id is null")
	}
	// 检查 Src 部分
	if req.SrcType == proto.VPNPolicyTypeIP {
		ip := net.ParseIP(req.SrcIP)
		if ip == nil || ip.String() != req.SrcIP {
			log.Println("request id:", resp.RequestID, " request type:", proto.VPNPolicyTypeIP, " params:", req.SrcIP, ", decode:", ip, " is invalid")
			return errors.New("invalid source IP address")
		}
	}

	if req.SrcType == proto.VPNPolicyTypeNetwork {
		ip, ipnet, err := net.ParseCIDR(req.SrcIP)
		if err != nil || ip == nil || ipnet == nil {
			log.Println("request id:", resp.RequestID, " request type:", proto.VPNPolicyTypeNetwork, " params:", req.SrcIP, " is invalid, error:", err)
			return errors.New("invalid source network CIDR")
		}
	}

	// 检查 Dst 部分
	if req.DstType == proto.VPNPolicyTypeIP {
		ip := net.ParseIP(req.DstIP)
		if ip == nil || ip.String() != req.DstIP {
			log.Println("request id:", resp.RequestID, " request type:", proto.VPNPolicyTypeIP, " params:", req.DstIP, ", decode:", ip, " is invalid")
			return errors.New("invalid destination IP address")
		}
	}

	if req.DstType == proto.VPNPolicyTypeNetwork {
		ip, ipnet, err := net.ParseCIDR(req.DstIP)
		if err != nil || ip == nil || ipnet == nil {
			log.Println("request id:", resp.RequestID, " request type:", proto.VPNPolicyTypeNetwork, " params:", req.DstIP, " is invalid, error:", err)
			return errors.New("invalid destination network CIDR")
		}
	}

	return nil
}

func MatchMyVPNPolicy(user *dao.User, req *proto.VPNPolicyRequest, resp *proto.GenerateResp) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Message = "no permission"
		resp.Code = proto.PermissionDenied
	} else {
		err := CheckVPNPolicyUpdateParam(resp, req)
		if err != nil {
			resp.Code = proto.ParameterError
			resp.Message = err.Error()
			return
		}

		policies, err := dao.GetVPNPolicyByServerID(req.ServerID)
		if err != nil {
			resp.Code = proto.OperationFailed
			resp.Message = "the server id is error"
			log.Println("[ERROR] request id:", resp.RequestID, " user:", user.ID, " get vpn policy dao err:", err)
			return
		}
		exist := false
		for _, policy := range policies {
			if MatchPolicy(req, &policy) == true {
				exist = true
				resp.Data = policy
				break
			}
		}

		if exist == false {
			//获取服务器配置
			resp.Data = 0 //默认无数据，匹配默认
		}
		resp.Code = proto.SuccessCode
		resp.Message = "success"
	}
}

func MatchPolicySrc(req *proto.VPNPolicyRequest, policy *proto.VPNPolicy) bool {
	switch policy.SrcType {
	case proto.VPNPolicyTypeIP:
		if policy.SrcIP != req.SrcIP {
			return false
		}
	case proto.VPNPolicyTypeNetwork:
		_, area, err := net.ParseCIDR(policy.SrcIP)
		if err != nil || area == nil {
			return false
		}
		if area.Contains(net.IP(req.SrcIP)) == false {
			return false
		}
	case proto.VPNPolicyTypeUserID:
		if policy.SrcUserID != req.SrcUserID {
			return false
		}
	case proto.VPNPolicyTypeGroupID:
		return false
	default:
		return false
	}

	return true
}

func MatchPolicyDst(req *proto.VPNPolicyRequest, policy *proto.VPNPolicy) bool {
	switch policy.DstType {
	case proto.VPNPolicyTypeIP:
		if policy.DstIP != req.DstIP {
			return false
		}
	case proto.VPNPolicyTypeNetwork:
		_, area, err := net.ParseCIDR(policy.DstIP)
		if err != nil || area == nil {
			return false
		}
		if area.Contains(net.IP(req.DstIP)) == false {
			return false
		}
	case proto.VPNPolicyTypeUserID:
		if policy.DstUserID != req.DstUserID {
			return false
		}
	case proto.VPNPolicyTypeGroupID:
		return false
	default:
		return false
	}
	return true
}

func MatchPolicy(req *proto.VPNPolicyRequest, policy *proto.VPNPolicy) bool {
	if MatchPolicySrc(req, policy) == false {
		return false
	}
	if MatchPolicyDst(req, policy) == false {
		return false
	}
	return true
}

func CreateMyVPNPolicy(user *dao.User, resp *proto.GenerateResp, req *proto.VPNPolicyRequest) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Message = "no permission"
		resp.Code = proto.PermissionDenied
	} else {
		err := CheckVPNPolicyUpdateParam(resp, req)
		if err != nil {
			resp.Code = proto.ParameterError
			resp.Message = err.Error()
			return
		}

		policy := &proto.VPNPolicy{
			VPNPolicyBase: req.VPNPolicyBase,
		}
		err = dao.CreateVPNPolicy(policy)
		if err != nil {
			log.Println("[ERROR] request id:", resp.RequestID, " user:", user.ID, " create vpn policy dao err:", err)
			resp.Code = proto.InternalServerError
			resp.Message = "failed to create policy"
		} else {
			SendVPNPolicyMsgToDPServer(proto.DPOpCodePolicyAdd, req.ServerID, policy)
			resp.Code = proto.SuccessCode
			resp.Message = "success"
		}
	}
}

func UpdateMyVPNPolicy(user *dao.User, resp *proto.GenerateResp, req *proto.VPNPolicyRequest) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Message = "no permission"
		resp.Code = proto.PermissionDenied
	} else {
		err := CheckVPNPolicyUpdateParam(resp, req)
		if err != nil {
			resp.Code = proto.ParameterError
			resp.Message = err.Error()
			return
		}

		policy := &proto.VPNPolicy{
			VPNPolicyBase: req.VPNPolicyBase,
		}
		err = dao.UpdateVPNPolicy(req.ID, policy)
		if err != nil {
			log.Println("[ERROR] request id:", resp.RequestID, " user:", user.ID, " update vpn policy dao err:", err)
			resp.Code = proto.InternalServerError
			resp.Message = "failed to update policy"
		} else {
			SendVPNPolicyMsgToDPServer(proto.DPOpCodePolicyUpdate, req.ServerID, policy)
			resp.Code = proto.SuccessCode
			resp.Message = "success"
		}
	}
}

func DeleteMyVPNPolicy(user *dao.User, resp *proto.GenerateResp, policyID uint, serverID string) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Message = "no permission"
		resp.Code = proto.PermissionDenied
	} else {
		var err error
		if serverID != "" {
			err = dao.DeleteVPNPolicyByServerID(serverID)
		} else if policyID > 0 {
			err = dao.DeleteVPNPolicyByID(policyID)
		}
		if err != nil {
			log.Println("[ERROR] request id:", resp.RequestID, " user:", user.ID, "server id", serverID, " delete vpn policy dao err:", err)
			resp.Code = proto.InternalServerError
			resp.Message = "failed to delete policy"
		} else {
			policy := proto.VPNPolicy{}
			policy.ID = policyID

			SendVPNPolicyMsgToDPServer(proto.DPOpCodePolicyDel, serverID, &policy)
			resp.Code = proto.SuccessCode
			resp.Message = "success"
		}
	}
}

func SendVPNAuthUserMsgToDPServer(opCode int, serverID string, authUser *proto.VPNAuthUserDPInfo) {
	var event proto.VPNDPServerEvent
	event.MsgType = proto.DPMsgAuthUserType
	event.OpCode = opCode
	event.AuthUser = authUser
	//加入消息队列
	key := "vpn_dp_event_" + serverID

	msg, err := json.Marshal(&event)

	if err != nil {
		log.Println("server id:", serverID, " auth user event to dp server encode err:", err)
		return
	}

	worker.Publish(key, string(msg), time.Second*10)
}

func SendVPNPolicyMsgToDPServer(opCode int, serverID string, policy *proto.VPNPolicy) {
	var event proto.VPNDPServerEvent
	event.MsgType = proto.DPMsgPolicyType
	event.OpCode = opCode
	event.VPNPolicy = policy
	//加入消息队列
	key := "vpn_dp_event_" + serverID

	msg, err := json.Marshal(&event)

	if err != nil {
		log.Println("server id:", serverID, " vpn policy event to dp server encode err:", err)
		return
	}

	worker.Publish(key, string(msg), time.Second*10)
}
