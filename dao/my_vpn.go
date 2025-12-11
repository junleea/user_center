package dao

import "user_center/proto"

func CreateMyVPNServerConfig(type_ int, attr, value string) error {
	db := GetDB()
	var config proto.MyVPNServerConfig
	config.Type = type_
	config.Attr = attr
	config.Value = value
	res := db.Create(&config)
	return res.Error
}

func GetMyVPNServerConfigByAttr(type_ int, attr string) proto.MyVPNServerConfig {
	db := GetDB()
	var config proto.MyVPNServerConfig
	db.Where("type = ? AND attr = ?", type_, attr).First(&config)
	return config
}

func UpdateMyVPNServerConfig(id, type_ int, attr, value string) error {
	db := GetDB()
	var config proto.MyVPNServerConfig
	config.Type = type_
	config.Attr = attr
	config.Value = value
	res := db.Model(&config).Where("id = ?", id).Updates(config)
	return res.Error
}

func UpdateMyVPNServerConfigByTypeAttr(type_ int, attr, value string) error {
	db := GetDB()
	var config proto.MyVPNServerConfig
	config.Type = type_
	config.Attr = attr
	config.Value = value
	res := db.Model(&config).Where("type = ?  AND attr = ?", type_, attr).Updates(config)
	return res.Error
}
func DeleteMyVPNServerConfigByID(id int) error {
	db := GetDB()
	var config proto.MyVPNServerConfig
	res := db.Model(&config).Where("id = ?", id).Delete(&config)
	return res.Error
}

func DeleteMyVPNServerConfigByType(type_ int, attr string) error {
	db := GetDB()
	var config proto.MyVPNServerConfig
	res := db.Model(&config).Where("type = ? AND attr = ?", type_, attr).Delete(&config)
	return res.Error
}

func GetMyVPNServerConfig() ([]proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config []proto.MyVPNServerConfig
	res := db.Where("type = ?", proto.VPNServerConfigTypeServer).Find(&config)
	return config, res.Error
}

func GetMyVPNServerConfigByServerID(serverID string) ([]proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config []proto.MyVPNServerConfig
	res := db.Where("type = ? ", proto.VPNServerConfigTypeServer).Find(&config)
	return config, res.Error
}

func GetMyVPNServerTunnelConfig() ([]proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config []proto.MyVPNServerConfig
	res := db.Where("type = ?", proto.VPNServerConfigTypeTunnel).Find(&config)
	return config, res.Error
}

func GetMyVPNServerTunnelConfigByName(name string) (proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config proto.MyVPNServerConfig
	res := db.Where("type = ? AND attr = ?", proto.VPNServerConfigTypeTunnel, name).First(&config)
	return config, res.Error
}

func GetMyVPNServerIPPoolConfig() ([]proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config []proto.MyVPNServerConfig
	res := db.Where("type = ?", proto.VPNServerConfigTypeAddressPool).Find(&config)
	return config, res.Error
}
func GetMyVPNServerIPPoolConfigByName(name string) (proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config proto.MyVPNServerConfig
	res := db.Where("type = ? AND attr = ?", proto.VPNServerConfigTypeAddressPool, name).First(&config)
	return config, res.Error
}
