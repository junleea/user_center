package service

import (
	"encoding/json"
	"errors"
	"log"
	"user_center/dao"
	"user_center/proto"
)

// 对model policy info进行管理
func GetAllModelPolicyInfo() ([]proto.GetModelPolicyResponse, error) {
	res, err := dao.GetAllModelPolicy()
	var resp []proto.GetModelPolicyResponse
	if err != nil {
		return resp, err
	}
	for _, v := range res {
		users, err2 := dao.GetDefaultUserInfoByModelPolicyID(v.ID)
		if err2 != nil {
			log.Println("[ERROR] GetDefaultUserInfoByModelPolicyID err:", err2.Error())
		} else {
			resp = append(resp, proto.GetModelPolicyResponse{
				Policy: v,
				Range:  users,
			})
		}

	}
	return resp, err
}

// 递归获取
func GetUserModelPolicy(user *dao.User) *proto.UserModelPolicy {
	//user policy info
	userPolicyInfo, err := dao.GetUserPolicyInfo(user.ID)
	if err != nil || userPolicyInfo == nil {
		//返回默认策略
		policy, err2 := dao.GetDefaultModelPolicy()
		if err2 != nil {
			log.Println("[ERROR] GetUserModelPolicy err:", err2.Error())
			return policy[0]
		}
		return policy[0]
	}

	if userPolicyInfo.ModelPolicyID == 0 {
		if user.Prev == 0 {
			//返回默认策略
			policy, err2 := dao.GetDefaultModelPolicy()
			if err2 != nil {
				log.Println("[ERROR] GetUserModelPolicy err:", err2.Error())
				return policy[0]
			}
			return policy[0]
		} else {
			userInfo := GetUserByIDWithCache(user.Prev)
			return GetUserModelPolicy(&userInfo)
		}
	}
	policy, err3 := dao.GetOneModelPolicy(userPolicyInfo.ModelPolicyID)
	if err3 != nil || policy == nil || len(policy) == 0 {
		log.Println("[ERROR] GetUserModelPolicy err:", err3.Error())
		return nil
	}
	return &policy[0]
}

// 递归获取
func GetUserModelPolicyWithFunctionID(user *dao.User, functionID int) *proto.UserModelPolicy {
	//user policy info
	userPolicyInfo, err := dao.GetUserPolicyInfo(user.ID)
	if err != nil || userPolicyInfo == nil {
		//返回默认策略
		policy, err2 := dao.GetDefaultModelPolicy()
		if err2 != nil {
			log.Println("[ERROR] GetUserModelPolicy err:", err2.Error())
			return policy[0]
		}
		return policy[0]
	}

	if userPolicyInfo.ModelPolicyID == 0 {
		if user.Prev == 0 {
			//返回默认策略
			policy, err2 := dao.GetDefaultModelPolicy()
			if err2 != nil {
				log.Println("[ERROR] GetUserModelPolicy err:", err2.Error())
				return policy[0]
			}
			return policy[0]
		} else {
			userInfo := GetUserByIDWithCache(user.Prev)
			return GetUserModelPolicy(&userInfo)
		}
	}
	policy, err3 := dao.GetOneModelPolicy(userPolicyInfo.ModelPolicyID)
	if err3 != nil || policy == nil || len(policy) == 0 {
		log.Println("[ERROR] GetUserModelPolicy err:", err3.Error())
		return nil
	}
	if policy[0].FunctionID != functionID {
		if user.Prev == 0 {
			//返回默认策略
			policy2, err2 := dao.GetDefaultModelPolicy()
			if err2 != nil {
				log.Println("[ERROR] GetUserModelPolicy err:", err2.Error())
				return policy2[0]
			}
			return policy2[0]
		} else {
			userInfo := GetUserByIDWithCache(user.Prev)
			return GetUserModelPolicyWithFunctionID(&userInfo, functionID)
		}
	}
	return &policy[0]
}

func GetUserModelInfo(req *proto.GetUserModelPolicyRequest) (proto.GetModelPolicyResponse, error) {
	var resp proto.GetModelPolicyResponse
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
			resp.Policy = *GetUserModelPolicy(&user)
			users, err2 := dao.GetDefaultUserInfoByModelPolicyID(resp.Policy.ID)
			if err2 != nil {
				log.Println("[ERROR] GetUserModelPolicy err:", err2.Error())
				err = err2
			} else {
				resp.Range = users
			}
		} else {
			log.Println("[ERROR] GetUserModelInfo user req user is invalid, req  userID:", req.UserID, " req user name:", req.UserName)
			err = errors.New("请求参数错误")
		}
	}

	return resp, err
}

func GetOneModelPolicyInfo(id int) (*[]proto.GetModelPolicyResponse, error) {
	res, err := dao.GetOneModelPolicy(id)
	var resp []proto.GetModelPolicyResponse
	if err != nil || len(res) == 0 {
		log.Println("[ERROR] GetOneModelInfo err:", err.Error())
	} else {
		for _, v := range res {
			users, err2 := dao.GetDefaultUserInfoByModelPolicyID(v.ID)
			if err2 != nil {
				log.Println("[ERROR] GetDefaultUserInfoByModelPolicyID err:", err2.Error())
				err = errors.New("get user info error")
			}
			resp = append(resp, proto.GetModelPolicyResponse{
				Policy: v,
				Range:  users,
			})
		}
	}
	return &resp, err
}

func DeleteModelPolicy(requestID string, user *dao.User, req *proto.ModelPolicyRequest) (code int, err error) {
	if user.Role != "admin" {
		code = proto.PermissionDenied
		err = errors.New("no Model")
		return code, err
	}
	err = dao.ResetUserModelPolicyInfo(req.ID)
	if err != nil {
		code = proto.OperationFailed
		err = errors.New("reset Model policy user failed")
	} else {
		err = dao.DelModelPolicy(req.ID)
		if err != nil {
			log.Println("[ERROR] request id:", requestID, ", DelModelPolicy err:", err.Error())
			code = proto.OperationFailed
			err = errors.New("delete Model policy failed")
		}
	}
	return code, err
}

func UpdateUserModelPolicy(user *dao.User, req *proto.ModelPolicyRequest, requestID string) (code int, err error) {
	if user.Role != proto.USER_IS_ADMIN {
		code = proto.PermissionDenied
		err = errors.New("no Model")
		return code, err
	}
	if req.ID <= 0 {
		code = proto.ParameterError
		err = errors.New("policy id is invalid")
		return code, err
	}
	modelPolicy, err := dao.GetOneModelPolicy(req.ID)
	if err != nil || len(modelPolicy) == 0 {
		code = proto.OperationFailed
		err = errors.New("get Model policy failed")
		return code, err
	}
	var policy proto.UserModelPolicy
	policy = modelPolicy[0]
	if req.PolicyName != "" {
		policy.Name = req.PolicyName
	}
	if req.PolicyInfo != "" {
		policy.Info = req.PolicyInfo
	}
	if req.FunctionID > 0 {
		policy.FunctionID = req.FunctionID
	}
	//model id 列表
	var strModelIDs string
	res, _ := json.Marshal(req.ModelID)
	strModelIDs = string(res)
	policy.ModelID = strModelIDs

	err = dao.UpdateModelPolicy(int(policy.ID), &policy)
	if err != nil {
		code = proto.OperationFailed
		err = errors.New("update Model policy failed")
	} else {
		//更新生效用户
		//先删除所有是这个的用户
		err = dao.ResetUserModelPolicyInfo(int(policy.ID))
		if err != nil {
			code = proto.OperationFailed
			err = errors.New("update Model policy failed")
		} else {
			//设置生效用户
			for _, v := range req.UserRange {
				//设置生效
				err = dao.UpdateUserModelPolicyInfo(v.ID, int(policy.ID))
				if err != nil {
					log.Println("[ERROR] request id:", requestID, ", UpdateUserModelPolicyInfo user id:", v.ID, " err:", err.Error())
				}
			}
			code, err = proto.SuccessCode, nil
		}
	}
	return code, err
}

func AddUserModelPolicy(requestID string, user *dao.User, req *proto.ModelPolicyRequest) (code int, err error) {
	if user.Role != proto.USER_IS_ADMIN {
		code = proto.PermissionDenied
		err = errors.New("no Model")
		return code, err
	}
	var policy proto.UserModelPolicy
	if req.PolicyName == "" {
		reqStr, _ := json.Marshal(req)
		log.Println("requestID: ", requestID, " add Model policy req:", string(reqStr))
		code = proto.ParameterError
		err = errors.New("policy name is empty")
		return code, err
	}
	policy.Name = req.PolicyName
	policy.Info = req.PolicyInfo
	policy.FunctionID = req.FunctionID
	//model id 列表
	var strModelIDs string
	res, _ := json.Marshal(req.ModelID)
	strModelIDs = string(res)
	policy.ModelID = strModelIDs

	err = dao.AddModelPolicy(&policy)
	if err != nil {
		code = proto.OperationFailed
		err = errors.New("add Model policy failed")
	} else {
		for _, v := range req.UserRange {
			//设置生效
			err = dao.UpdateUserModelPolicyInfo(v.ID, int(policy.ID))
			if err != nil {
				log.Println("[ERROR]", " requestID: ", requestID, " AddModelPolicy user id:", v.ID, " err:", err.Error())
			}
		}
		code, err = proto.SuccessCode, nil
	}
	return code, err
}
