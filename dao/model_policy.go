package dao

import "user_center/proto"

func AddModelPolicy(policy *proto.UserModelPolicy) error {
	db2 := GetDB()
	res := db2.Model(&proto.UserModelPolicy{}).Create(policy)
	return res.Error
}
