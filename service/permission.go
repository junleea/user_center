package service

import (
	"errors"
	"log"
	"user_center/dao"
	"user_center/proto"
)

// 递归获取
func GetUserPermissionPolicy(user *dao.User) *proto.PermissionPolicy {
	//user policy info
	userPolicyInfo, err := dao.GetUserPolicyInfo(user.ID)
	if err != nil || userPolicyInfo == nil {
		//返回默认策略
		policy, err2 := dao.GetDefaultPermissionPolicy()
		if err2 != nil {
			log.Println("[ERROR] GetUserPermissionPolicy err:", err2.Error())
			return policy[0]
		}
		return policy[0]
	}

	if userPolicyInfo.PermissionPolicyID == 0 {
		if user.Prev == 0 {
			//返回默认策略
			policy, err2 := dao.GetDefaultPermissionPolicy()
			if err2 != nil {
				log.Println("[ERROR] GetUserPermissionPolicy err:", err2.Error())
				return policy[0]
			}
			return policy[0]
		} else {
			user_info := GetUserByIDWithCache(user.Prev)
			return GetUserPermissionPolicy(&user_info)
		}
	}
	policy, err3 := dao.GetOnePermissionPolicy(userPolicyInfo.PermissionPolicyID)
	if err3 != nil || policy == nil || len(policy) == 0 {
		log.Println("[ERROR] GetUserPermissionPolicy err:", err3.Error())
		return nil
	}
	return &policy[0]
}

// 对permission policy info进行管理
func GetAllPermissionInfo() ([]proto.GetPermissionPolicyResponse, error) {
	res, err := dao.GetAllPermissionPolicy()
	var resp []proto.GetPermissionPolicyResponse
	if err != nil {
		return resp, err
	}
	for _, v := range res {
		users, err2 := dao.GetDefaultUserInfoByPermissionPolicyID(v.ID)
		if err2 != nil {
			log.Println("[ERROR] GetDefaultUserInfoByPermissionPolicyID err:", err2.Error())
		} else {
			resp = append(resp, proto.GetPermissionPolicyResponse{
				Policy: v,
				Range:  users,
			})
		}

	}
	return resp, err
}

func GetOnePermissionInfo(id int) (*[]proto.GetPermissionPolicyResponse, error) {
	res, err := dao.GetOnePermissionPolicy(id)
	var resp []proto.GetPermissionPolicyResponse
	if err != nil || len(res) == 0 {
		log.Println("[ERROR] GetOnePermissionInfo err:", err.Error())
	} else {
		for _, v := range res {
			users, err2 := dao.GetDefaultUserInfoByPermissionPolicyID(v.ID)
			if err2 != nil {
				log.Println("[ERROR] GetDefaultUserInfoByPermissionPolicyID err:", err2.Error())
				err = errors.New("get user info error")
			}
			resp = append(resp, proto.GetPermissionPolicyResponse{
				Policy: v,
				Range:  users,
			})
		}
	}
	return &resp, err
}

func GetUserPermissionInfo(req *proto.GetUserPermissionPolicyRequest) (proto.GetPermissionPolicyResponse, error) {
	var resp proto.GetPermissionPolicyResponse
	var err error
	if req.UserID == 0 && req.UserName == "" {
		err = errors.New("请求参数错误")
	} else {
		var user dao.User
		if req.UserID > 0 {
			user = GetUserByIDWithCache(int(req.UserID))
		} else if req.UserName != "" {
			user = GetUserByName(req.UserName)
		}
		if user.ID > 0 {
			resp.Policy = *GetUserPermissionPolicy(&user)
			users, err2 := dao.GetDefaultUserInfoByPermissionPolicyID(resp.Policy.ID)
			if err2 != nil {
				log.Println("[ERROR] GetUserPermissionPolicy err:", err2.Error())
				err = err2
			} else {
				resp.Range = users
			}
		} else {
			log.Println("[ERROR] GetUserPermissionInfo user req user is invalid, req  userID:", req.UserID, " req user name:", req.UserName)
			err = errors.New("请求参数错误")
		}
	}

	return resp, err
}

func AddPermissionPolicy(user *dao.User, req *proto.PermissionPolicyRequest) (code int, err error) {
	if user.Role != "admin" {
		code = proto.PermissionDenied
		err = errors.New("no permission")
		return code, err
	}
	var policy proto.PermissionPolicy
	if req.PolicyName == "" {
		code = proto.ParameterError
		err = errors.New("policy name is empty")
		return code, err
	}
	policy.Name = req.PolicyName
	policy.Info = req.PolicyInfo
	policy.Redis = req.Redis
	policy.Upload = req.Upload
	policy.Device = req.Device
	policy.File = req.File
	policy.CID = req.CID
	policy.RunShell = req.RunShell
	policy.UploadSize = req.UploadSize
	policy.UploadMaxSize = req.UploadMaxSize
	policy.SendMail = req.SendMail
	err = dao.AddPermissionPolicy(&policy)
	if err != nil {
		for _, v := range req.UserRange {
			//设置生效
			err = dao.UpdateUserPermissionPolicyInfo(v.ID, int(policy.ID))
			if err != nil {
				log.Println("[ERROR] AddPermissionPolicy user id:", v.ID, " err:", err.Error())
			}
		}
		code = proto.OperationFailed
		err = errors.New("add permission policy failed")
	} else {
		code, err = proto.SuccessCode, nil
	}
	return code, err
}

func DeletePermissionPolicy(user *dao.User, req *proto.PermissionPolicyRequest) (code int, err error) {
	if user.Role != "admin" {
		code = proto.PermissionDenied
		err = errors.New("no permission")
		return code, err
	}
	err = dao.ResetUserPermissionInfo(req.ID)
	if err != nil {
		code = proto.OperationFailed
		err = errors.New("reset permission policy user failed")
	} else {
		err = dao.DelPermissionPolicy(req.ID)
		if err != nil {
			code = proto.OperationFailed
			err = errors.New("delete permission policy failed")
		}
	}
	return code, err
}

func UpdatePermissionPolicy(user *dao.User, req *proto.PermissionPolicyRequest) (code int, err error) {
	if user.Role != proto.USER_IS_ADMIN {
		code = proto.PermissionDenied
		err = errors.New("no permission")
		return code, err
	}
	permissionPolicy, err := dao.GetOnePermissionPolicy(req.ID)
	if err != nil {
		return 0, err
	}
	var policy proto.PermissionPolicy
	policy = permissionPolicy[0]
	if req.PolicyName != "" {
		policy.Name = req.PolicyName
	}
	if req.PolicyInfo != "" {
		policy.Info = req.PolicyInfo
	}
	if req.Redis != 0 {
		policy.Redis = req.Redis
	}
	if req.Upload != 0 {
		policy.Upload = req.Upload
	}

	if req.Device != 0 {
		policy.Device = req.Device
	}

	if req.File != 0 {
		policy.File = req.File
	}

	if req.CID != 0 {
		policy.CID = req.CID
	}
	if req.RunShell != 0 {
		policy.RunShell = req.RunShell
	}
	if req.UploadSize != 0 {
		policy.UploadSize = req.UploadSize
	}

	if req.UploadMaxSize != 0 {
		policy.UploadMaxSize = req.UploadMaxSize
	}
	if req.SendMail != 0 {
		policy.SendMail = req.SendMail
	}

	err = dao.UpdatePermissionPolicy(int(policy.ID), &policy)
	if err != nil {
		code = proto.OperationFailed
		err = errors.New("add permission policy failed")
	} else {
		//更新生效用户
		//先删除所有是这个的用户
		err = dao.ResetUserPermissionInfo(int(policy.ID))
		if err != nil {
			code = proto.OperationFailed
			err = errors.New("add permission policy failed")
		} else {
			//设置生效用户
			for _, v := range req.UserRange {
				//设置生效
				err = dao.UpdateUserPermissionPolicyInfo(v.ID, int(policy.ID))
				if err != nil {
					log.Println("[ERROR] AddPermissionPolicy user id:", v.ID, " err:", err.Error())
				}
			}
			code, err = proto.SuccessCode, nil
		}
	}
	return code, err
}
