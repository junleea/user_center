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
