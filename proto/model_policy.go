package proto

import "gorm.io/gorm"

type UserModelPolicy struct {
	gorm.Model
	Name       string `gorm:"column:name" json:"name"`
	Info       string `gorm:"column:info" json:"info"`
	FunctionID int    `gorm:"column:function_id" json:"function_id"` //功能id
	ModelID    string `gorm:"column:model_id" json:"model_id"`       //模型id列表
}

type ModelPolicyRequest struct {
	ID         int         `json:"id" form:"id"`
	PolicyName string      `json:"policy_name" form:"policy_name"`
	PolicyInfo string      `json:"policy_info" form:"policy_info"`
	FunctionID int         `json:"function_id" form:"function_id"`
	ModelID    []GeneralID `json:"model_id" form:"model_id"`
	//生效范围
	UserRange []UserID `json:"user_range" form:"user_range"`
}

type GeneralID struct {
	ID int `json:"id" form:"id"`
}

type GetUserModelPolicyRequest struct {
	Type          int    `json:"type" form:"type"` //类型，0， 为all, 1为指定用户/用户id， 2为获取指定id的policy
	UserID        uint   `json:"user_id" form:"user_id"`
	UserName      string `form:"user_name" json:"user_name"`
	FunctionID    int    `json:"function_id" form:"function_id"`
	ModelPolicyID int    `json:"model_policy_id" form:"model_policy_id"`
}

type GetModelPolicyResponse struct {
	Policy UserModelPolicy   `json:"policy" form:"policy"`
	Range  []UserDefaultInfo `json:"range" form:"range"`
}
