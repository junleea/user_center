package service

import (
	"errors"
	"log"
	"net"
	"user_center/dao"
	"user_center/proto"
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
			resp.Code = proto.SuccessCode
			resp.Message = "success"
		}
	}
}
