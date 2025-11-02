package proto

import "gorm.io/gorm"

type PermissionPolicy struct {
	gorm.Model
	Redis         int `gorm:"column:redis" json:"redis"` //1有权限
	RunShell      int `gorm:"column:run" json:"run_shell"`
	Upload        int `gorm:"column:upload" json:"upload"`
	CID           int `gorm:"column:cid" json:"cid"`
	File          int `gorm:"column:file" json:"file"`                       //系统文件
	Device        int `gorm:"column:device" json:"device"`                   //设备管理
	UploadSize    int `gorm:"column:upload_size" json:"upload_size"`         //单个上传文件限制
	UploadMaxSize int `gorm:"column:upload_max_size" json:"upload_max_size"` //上传最大空间
	SendMail      int `gorm:"column:send_mail" json:"send_mail"`             //发送邮件
}

type UserPolicyInfo struct {
	ID                 uint `gorm:"primarykey" json:"user_id"`                               //user  id
	PermissionPolicyID int  `gorm:"column:permission_policy_id" json:"permission_policy_id"` //permission policy id
}

type PermissionPolicyRequest struct {
	ID            int `json:"id" form:"id"`
	Redis         int `json:"redis" form:"redis"` //1有权限
	RunShell      int `json:"run_shell" form:"run_shell"`
	Upload        int `json:"upload" form:"upload"`
	CID           int `json:"cid" form:"cid"`
	File          int `json:"file" form:"file"`                       //系统文件
	Device        int `json:"device" form:"device"`                   //设备管理
	UploadSize    int `json:"upload_size" form:"upload_size"`         //单个上传文件限制
	UploadMaxSize int `json:"upload_max_size" form:"upload_max_size"` //上传最大空间
	SendMail      int `json:"send_mail" form:"send_mail"`             //发送邮件
	//生效范围
	UserRange []UserID `json:"user_range" form:"user_range"`
}

type UserID struct {
	ID uint `json:"id" form:"id"`
}
