package dao

import "user_center/proto"

func AddModelPolicy(policy *proto.UserModelPolicy) error {
	db2 := GetDB()
	res := db2.Model(&proto.UserModelPolicy{}).Create(policy)
	return res.Error
}

func UpdateModelPolicy(id int, policy *proto.UserModelPolicy) error {
	db2 := GetDB()
	res := db2.Where("id = ?", id).Updates(policy)
	return res.Error
}

func DelModelPolicy(policyID int) error {
	db2 := GetDB()
	res := db2.Delete(&proto.UserModelPolicy{}, policyID)
	return res.Error
}

func GetOneModelPolicy(policyID int) ([]proto.UserModelPolicy, error) {
	db2 := GetDB()
	var policy []proto.UserModelPolicy
	res := db2.Model(&proto.UserModelPolicy{}).Where("id = ?", policyID).Find(&policy)
	return policy, res.Error
}

func GetAllModelPolicy() ([]proto.UserModelPolicy, error) {
	db2 := GetDB()
	var policy []proto.UserModelPolicy
	res := db2.Model(&proto.UserModelPolicy{}).Find(&policy)
	return policy, res.Error
}

// 通过policy id获取生效用户
func GetDefaultUserInfoByModelPolicyID(id uint) ([]proto.UserDefaultInfo, error) {
	db2 := GetDB()
	var userInfo []proto.UserDefaultInfo
	err := db2.Table("users").
		Select("users.id, users.type, users.prev, users.name").
		Joins("JOIN user_policy_infos ON user_policy_infos.id = users.id").
		Where("user_policy_infos.model_policy_id = ?", id).
		Find(&userInfo).Error
	return userInfo, err
}

// 更新，先查看是否存在
func UpdateUserModelPolicyInfo(userId uint, modelPolicyId int) error {
	db2 := GetDB()
	policy, err := GetUserPolicyInfo(userId)
	if err != nil || policy == nil || policy.ID == 0 {
		//新建
		var userPolicy proto.UserPolicyInfo
		userPolicy.ModelPolicyID = modelPolicyId
		userPolicy.ID = userId
		err = AddUserPolicyInfo(&userPolicy)
		return err
	}
	res := db2.Model(&proto.UserPolicyInfo{}).Where("id = ?", userId).Update("model_policy_id", modelPolicyId)
	return res.Error
}

func ResetUserModelPolicyInfo(modelPolicyId int) error {
	db2 := GetDB()
	res := db2.Model(&proto.UserPolicyInfo{}).Where("model_policy_id = ?", modelPolicyId).Update("model_policy_id", 0) //设置为初始值
	return res.Error
}

func GetDefaultModelPolicy() ([]*proto.UserModelPolicy, error) {
	db2 := GetDB()
	var policy []*proto.UserModelPolicy
	res := db2.Model(&proto.UserModelPolicy{}).First(&policy) //默认
	return policy, res.Error
}
