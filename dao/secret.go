package dao

import (
	"gorm.io/gorm"
	"user_center/proto"
)

func CreateSecret(secret proto.Secret) error {
	var db2 *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	} else {
		db2 = DB
	}
	return db2.Create(&secret).Error
}

func GetSecretByID(id uint) (proto.Secret, error) {
	var secret proto.Secret
	var db2 *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	} else {
		db2 = DB
	}
	err := db2.Where("id = ?", id).First(&secret).Error
	return secret, err
}

func GetSecretByMd5(md5 string) (proto.Secret, error) {
	var secret proto.Secret
	var db2 *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	} else {
		db2 = DB
	}
	err := db2.Where("secret_md5 = ?", md5).First(&secret).Error
	return secret, err
}

func GetSecretKeyBySecret(secret_ string) (proto.Secret, error) {
	var secret proto.Secret
	var db2 *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	} else {
		db2 = DB
	}
	err := db2.Where("secret_key = ?", secret_).First(&secret).Error
	return secret, err
}

// 根据ip获取地址信息
func GetIPAddressInfo(ip string) proto.LocalIPDataBase {
	var result proto.LocalIPDataBase
	var db2 *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	} else {
		db2 = DB
	}
	err := db2.Where("ip = ?", ip).First(&result).Error
	if err != nil {
		return result
	}
	return result
}

// 添加地址信息
func AddIPAddressInfo(ip string, info string) error {
	var db2 *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	} else {
		db2 = DB
	}
	ip_info := proto.LocalIPDataBase{ip, info}
	err := db2.Create(&ip_info).Error
	return err
}

// 更新地址信息
func UpdateIPAddressInfo(ip string, info string) error {
	var db2 *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	} else {
		db2 = DB
	}
	ip_info := proto.LocalIPDataBase{ip, info}
	err := db2.Updates(&ip_info).Error
	return err
}
