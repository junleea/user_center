package service

import (
	"log"
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
func CreateMyVPNPolicy(user *dao.User, resp *proto.GenerateResp, req *proto.VPNPolicyRequest) {
	if user.Role != proto.USER_IS_ADMIN {
		resp.Message = "no permission"
		resp.Code = proto.PermissionDenied
	} else {
		policy := &proto.VPNPolicy{
			VPNPolicyBase: req.VPNPolicyBase,
		}
		err := dao.CreateVPNPolicy(policy)
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
		policy := &proto.VPNPolicy{
			VPNPolicyBase: req.VPNPolicyBase,
		}
		err := dao.UpdateVPNPolicy(req.ID, policy)
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
