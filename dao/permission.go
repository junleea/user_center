package dao

import "user_center/proto"

func AddPermissionPolicy(policy *proto.PermissionPolicy) error {
	db2 := GetDB()
	res := db2.Model(proto.PermissionPolicy{}).Create(policy)
	return res.Error
}

func UpdatePermissionPolicy(id int, policy *proto.PermissionPolicy) error {
	db2 := GetDB()
	res := db2.Where("id = ?", id).Updates(policy)
	return res.Error
}

func DelPermissionPolicy(policyID int) error {
	db2 := GetDB()
	res := db2.Where("id = ?", policyID).Delete(proto.PermissionPolicy{})
	return res.Error
}

func GetDefaultPermissionPolicy() ([]*proto.PermissionPolicy, error) {
	db2 := GetDB()
	var policy []*proto.PermissionPolicy
	res := db2.Model(proto.PermissionPolicy{}).First(&policy) //默认
	return policy, res.Error
}

func GetOnePermissionPolicy(policyID int) ([]proto.PermissionPolicy, error) {
	db2 := GetDB()
	var policy []proto.PermissionPolicy
	res := db2.Model(proto.PermissionPolicy{}).Where("id = ?", policyID).Find(&policy)
	return policy, res.Error
}

func GetAllPermissionPolicy() ([]proto.PermissionPolicy, error) {
	db2 := GetDB()
	var policy []proto.PermissionPolicy
	res := db2.Model(proto.PermissionPolicy{}).Find(&policy)
	return policy, res.Error
}

// permission policy user
func GetUserPolicyInfo(id uint) (*proto.UserPolicyInfo, error) {
	db2 := GetDB()
	var policyInfo proto.UserPolicyInfo
	res := db2.Model(proto.UserPolicyInfo{}).Where("id = ?", id).Find(&policyInfo)
	return &policyInfo, res.Error
}

// 更新，先查看是否存在
func UpdateUserPermissionPolicyInfo(user_id uint, permission_policy_id int) error {
	db2 := GetDB()
	policy, err := GetUserPolicyInfo(user_id)
	if err != nil || policy == nil || policy.ID == 0 {
		//新建
		var user_policy proto.UserPolicyInfo
		user_policy.PermissionPolicyID = permission_policy_id
		user_policy.ID = user_id
		err = AddUserPolicyInfo(&user_policy)
		return err
	}
	res := db2.Model(&proto.UserPolicyInfo{}).Where("id = ?", user_id).Update("permission_policy_id", permission_policy_id)
	return res.Error
}

func UpdateUserPolicyInfo(id int, policy *proto.UserPolicyInfo) error {
	db2 := GetDB()
	db2.Model(proto.UserPolicyInfo{}).Where("id = ?", id).Updates(policy)
	return db2.Error
}

func AddUserPolicyInfo(policyInfo *proto.UserPolicyInfo) error {
	db2 := GetDB()
	res := db2.Model(proto.UserPolicyInfo{}).Create(policyInfo)
	return res.Error
}

func ResetUserPermissionInfo(permissionPolicyId int) error {
	db2 := GetDB()
	res := db2.Model(&proto.UserPolicyInfo{}).Where("permission_policy_id = ?", permissionPolicyId).Update("permission_policy_id", 0) //设置为初始值
	return res.Error
}
