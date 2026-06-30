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

func GetMyVPNServerConfigByType(type_ int) []proto.MyVPNServerConfig {
	db := GetDB()
	var config []proto.MyVPNServerConfig
	db.Where("type = ?", type_).Find(&config)
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
	res := db.Where("id = ?", id).Delete(&proto.MyVPNServerConfig{})
	return res.Error
}

func DeleteMyVPNServerConfigByType(type_ int, attr string) error {
	db := GetDB()
	res := db.Where("type = ? AND attr = ?", type_, attr).Delete(&proto.MyVPNServerConfig{})
	return res.Error
}

func GetMyVPNServerConfig() ([]proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config []proto.MyVPNServerConfig
	res := db.Where("type = ?", proto.VPNServerConfigTypeServer).Find(&config)
	return config, res.Error
}

func GetMyVPNServerConfigByServerID(serverID string) (proto.MyVPNServerConfig, error) {
	db := GetDB()
	var config proto.MyVPNServerConfig
	res := db.Where("type = ? AND attr = ?", proto.VPNServerConfigTypeServer, serverID).First(&config)
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

func CreateVPNPolicy(policy *proto.VPNPolicy) error {
	db := GetDB()
	res := db.Create(policy)
	return res.Error
}

func DeleteVPNPolicyByID(id uint) error {
	db := GetDB()
	res := db.Where("id = ?", id).Delete(&proto.VPNPolicy{})
	return res.Error
}

func DeleteVPNPolicyByServerID(serverID string) error {
	db := GetDB()
	res := db.Where("server_id = ?", serverID).Delete(&proto.VPNPolicy{})
	return res.Error
}

func UpdateVPNPolicy(id uint, policy *proto.VPNPolicy) error {
	db := GetDB()
	res := db.Model(&proto.VPNPolicy{}).Where("id = ?", id).Updates(policy)
	return res.Error
}

func GetVPNPolicyByServerID(serverID string) ([]proto.VPNPolicy, error) {
	db := GetDB()
	var policies []proto.VPNPolicy
	res := db.Where("server_id = ?", serverID).Find(&policies)
	return policies, res.Error
}

func GetVPNPolicyByID(id uint) (proto.VPNPolicy, error) {
	db := GetDB()
	var policy proto.VPNPolicy
	res := db.Where("id = ?", id).First(&policy)
	return policy, res.Error
}

// CreateMyVPNUserLoginInfo 创建用户登录记录
func CreateMyVPNUserLoginInfo(info *proto.MyVPNUserLoginInfo) error {
	db := GetDB()
	res := db.Create(info)
	return res.Error
}

// GetMyVPNUserLoginInfoByID 根据ID获取用户登录记录
func GetMyVPNUserLoginInfoByID(id uint) (*proto.MyVPNUserLoginInfo, error) {
	db := GetDB()
	var info proto.MyVPNUserLoginInfo
	res := db.Where("id = ?", id).First(&info)
	if res.Error != nil {
		return nil, res.Error
	}
	return &info, nil
}

// GetMyVPNUserLoginInfoByUserID 根据用户ID获取登录记录
func GetMyVPNUserLoginInfoByUserID(userID uint) ([]proto.MyVPNUserLoginInfo, error) {
	db := GetDB()
	var infos []proto.MyVPNUserLoginInfo
	res := db.Where("user_id = ?", userID).Order("created_at desc").Find(&infos)
	return infos, res.Error
}

// GetMyVPNUserLoginInfoByServerID 根据服务器ID获取登录记录
func GetMyVPNUserLoginInfoByServerID(serverID string) ([]proto.MyVPNUserLoginInfo, error) {
	db := GetDB()
	var infos []proto.MyVPNUserLoginInfo
	res := db.Where("server_id = ?", serverID).Order("created_at desc").Find(&infos)
	return infos, res.Error
}

// GetMyVPNUserLoginInfoByHostID 根据HostID获取登录记录
func GetMyVPNUserLoginInfoByHostID(hostID string) ([]proto.MyVPNUserLoginInfo, error) {
	db := GetDB()
	var infos []proto.MyVPNUserLoginInfo
	res := db.Where("host_id = ?", hostID).Order("created_at desc").Find(&infos)
	return infos, res.Error
}

// GetMyVPNUserOnlineStatus 获取用户在线状态（最近的登录事件且没有对应的登出事件）
func GetMyVPNUserOnlineStatus(userID uint) (*proto.MyVPNUserLoginInfo, error) {
	db := GetDB()
	var info proto.MyVPNUserLoginInfo
	// 查询最近的登录记录
	res := db.Where("user_id = ? AND event = ?", userID, proto.UserLoginEvent).
		Order("created_at desc").
		First(&info)
	if res.Error != nil {
		return nil, res.Error
	}

	// 检查是否有对应的登出记录
	var logoutInfo proto.MyVPNUserLoginInfo
	res = db.Where("user_id = ? AND event = ? AND created_at > ?", userID, proto.UserLogoutEvent, info.CreatedAt).
		First(&logoutInfo)
	if res.Error == nil {
		// 用户已登出
		return nil, nil
	}

	return &info, nil
}

// UpdateMyVPNUserLoginInfo 更新用户登录记录
func UpdateMyVPNUserLoginInfo(id uint, info *proto.MyVPNUserLoginInfo) error {
	db := GetDB()
	res := db.Model(&proto.MyVPNUserLoginInfo{}).Where("id = ?", id).Updates(info)
	return res.Error
}

// DeleteMyVPNUserLoginInfoByID 根据ID删除用户登录记录
func DeleteMyVPNUserLoginInfoByID(id uint) error {
	db := GetDB()
	res := db.Where("id = ?", id).Delete(&proto.MyVPNUserLoginInfo{})
	return res.Error
}

// DeleteMyVPNUserLoginInfoByUserID 根据用户ID删除所有登录记录
func DeleteMyVPNUserLoginInfoByUserID(userID uint) error {
	db := GetDB()
	res := db.Where("user_id = ?", userID).Delete(&proto.MyVPNUserLoginInfo{})
	return res.Error
}

// DeleteMyVPNUserLoginInfoByServerID 根据服务器ID删除所有登录记录
func DeleteMyVPNUserLoginInfoByServerID(serverID string) error {
	db := GetDB()
	res := db.Where("server_id = ?", serverID).Delete(&proto.MyVPNUserLoginInfo{})
	return res.Error
}

// ListMyVPNUserLoginInfo 分页获取用户登录记录
func ListMyVPNUserLoginInfo(page, pageSize int) ([]proto.MyVPNUserLoginInfo, int64, error) {
	db := GetDB()
	var infos []proto.MyVPNUserLoginInfo
	var total int64

	// 获取总数
	db.Model(&proto.MyVPNUserLoginInfo{}).Count(&total)

	// 分页查询
	offset := (page - 1) * pageSize
	res := db.Order("created_at desc").Offset(offset).Limit(pageSize).Find(&infos)
	return infos, total, res.Error
}

// ==================== VPNEventLog 相关操作 ====================

// CreateVPNEventLog 创建VPN事件日志
func CreateVPNEventLog(eventLog *VPNEventLog) error {
	db := GetDB()
	res := db.Create(eventLog)
	return res.Error
}

// GetVPNEventLogByID 根据ID获取VPN事件日志
func GetVPNEventLogByID(id uint) (*VPNEventLog, error) {
	db := GetDB()
	var eventLog VPNEventLog
	res := db.Where("id = ?", id).First(&eventLog)
	if res.Error != nil {
		return nil, res.Error
	}
	return &eventLog, nil
}

// GetVPNEventLogByServerID 根据服务器ID获取VPN事件日志
func GetVPNEventLogByServerID(serverID string) ([]VPNEventLog, error) {
	db := GetDB()
	var eventLogs []VPNEventLog
	res := db.Where("server_id = ?", serverID).Order("event_time desc").Find(&eventLogs)
	return eventLogs, res.Error
}

// GetVPNEventLogByUserID 根据用户ID获取VPN事件日志
func GetVPNEventLogByUserID(userID uint) ([]VPNEventLog, error) {
	db := GetDB()
	var eventLogs []VPNEventLog
	res := db.Where("user_id = ?", userID).Order("event_time desc").Find(&eventLogs)
	return eventLogs, res.Error
}

// GetVPNEventLogByEventType 根据事件类型获取VPN事件日志
func GetVPNEventLogByEventType(eventType VPNEventType) ([]VPNEventLog, error) {
	db := GetDB()
	var eventLogs []VPNEventLog
	res := db.Where("event = ?", eventType).Order("event_time desc").Find(&eventLogs)
	return eventLogs, res.Error
}

// GetVPNEventLogByServerIDAndEventType 根据服务器ID和事件类型获取VPN事件日志
func GetVPNEventLogByServerIDAndEventType(serverID string, eventType VPNEventType) ([]VPNEventLog, error) {
	db := GetDB()
	var eventLogs []VPNEventLog
	res := db.Where("server_id = ? AND event = ?", serverID, eventType).Order("event_time desc").Find(&eventLogs)
	return eventLogs, res.Error
}

// UpdateVPNEventLog 更新VPN事件日志
func UpdateVPNEventLog(id uint, eventLog *VPNEventLog) error {
	db := GetDB()
	res := db.Model(&VPNEventLog{}).Where("id = ?", id).Updates(eventLog)
	return res.Error
}

// DeleteVPNEventLogByID 根据ID删除VPN事件日志
func DeleteVPNEventLogByID(id uint) error {
	db := GetDB()
	res := db.Where("id = ?", id).Delete(&VPNEventLog{})
	return res.Error
}

// DeleteVPNEventLogByServerID 根据服务器ID删除所有VPN事件日志
func DeleteVPNEventLogByServerID(serverID string) error {
	db := GetDB()
	res := db.Where("server_id = ?", serverID).Delete(&VPNEventLog{})
	return res.Error
}

// DeleteVPNEventLogByUserID 根据用户ID删除所有VPN事件日志
func DeleteVPNEventLogByUserID(userID uint) error {
	db := GetDB()
	res := db.Where("user_id = ?", userID).Delete(&VPNEventLog{})
	return res.Error
}

// ListVPNEventLog 分页获取VPN事件日志
func ListVPNEventLog(page, pageSize int) ([]VPNEventLog, int64, error) {
	db := GetDB()
	var eventLogs []VPNEventLog
	var total int64

	// 获取总数
	db.Model(&VPNEventLog{}).Count(&total)

	// 分页查询
	offset := (page - 1) * pageSize
	res := db.Order("event_time desc").Offset(offset).Limit(pageSize).Find(&eventLogs)
	return eventLogs, total, res.Error
}

// ==================== VPNAuthUserDPInfoModel 相关操作 ====================

// CreateVPNAuthUserDPInfo 创建VPN用户连接信息
func CreateVPNAuthUserDPInfo(info *VPNAuthUserDPInfoModel) error {
	db := GetDB()
	res := db.Create(info)
	return res.Error
}

// GetVPNAuthUserDPInfoByID 根据ID获取VPN用户连接信息
func GetVPNAuthUserDPInfoByID(id uint) (*VPNAuthUserDPInfoModel, error) {
	db := GetDB()
	var info VPNAuthUserDPInfoModel
	res := db.Where("id = ?", id).First(&info)
	if res.Error != nil {
		return nil, res.Error
	}
	return &info, nil
}

// GetVPNAuthUserDPInfoByUUID 根据UUID获取VPN用户连接信息
func GetVPNAuthUserDPInfoByUUID(uuid string) (*VPNAuthUserDPInfoModel, error) {
	db := GetDB()
	var info VPNAuthUserDPInfoModel
	res := db.Where("uuid = ?", uuid).First(&info)
	if res.Error != nil {
		return nil, res.Error
	}
	return &info, nil
}

// GetVPNAuthUserDPInfoByServerID 根据服务器ID获取VPN用户连接信息
func GetVPNAuthUserDPInfoByServerID(serverID string) ([]VPNAuthUserDPInfoModel, error) {
	db := GetDB()
	var infos []VPNAuthUserDPInfoModel
	res := db.Where("server_id = ?", serverID).Find(&infos)
	return infos, res.Error
}

// GetVPNAuthUserDPInfoByUserID 根据用户ID获取VPN用户连接信息
func GetVPNAuthUserDPInfoByUserID(userID uint) ([]VPNAuthUserDPInfoModel, error) {
	db := GetDB()
	var infos []VPNAuthUserDPInfoModel
	res := db.Where("user_id = ?", userID).Find(&infos)
	return infos, res.Error
}

// UpdateVPNAuthUserDPInfo 更新VPN用户连接信息
func UpdateVPNAuthUserDPInfo(id uint, info *VPNAuthUserDPInfoModel) error {
	db := GetDB()
	res := db.Model(&VPNAuthUserDPInfoModel{}).Where("id = ?", id).Updates(info)
	return res.Error
}

// DeleteVPNAuthUserDPInfoByID 根据ID删除VPN用户连接信息
func DeleteVPNAuthUserDPInfoByID(id uint) error {
	db := GetDB()
	res := db.Where("id = ?", id).Delete(&VPNAuthUserDPInfoModel{})
	return res.Error
}

// DeleteVPNAuthUserDPInfoByUUID 根据UUID删除VPN用户连接信息
func DeleteVPNAuthUserDPInfoByUUID(uuid string) error {
	db := GetDB()
	res := db.Where("uuid = ?", uuid).Delete(&VPNAuthUserDPInfoModel{})
	return res.Error
}

// DeleteVPNAuthUserDPInfoByServerID 根据服务器ID删除所有VPN用户连接信息
func DeleteVPNAuthUserDPInfoByServerID(serverID string) error {
	db := GetDB()
	res := db.Where("server_id = ?", serverID).Delete(&VPNAuthUserDPInfoModel{})
	return res.Error
}

// DeleteVPNAuthUserDPInfoByUserID 根据用户ID删除所有VPN用户连接信息
func DeleteVPNAuthUserDPInfoByUserID(userID uint) error {
	db := GetDB()
	res := db.Where("user_id = ?", userID).Delete(&VPNAuthUserDPInfoModel{})
	return res.Error
}

// ListVPNAuthUserDPInfo 分页获取VPN用户连接信息
func ListVPNAuthUserDPInfo(page, pageSize int) ([]VPNAuthUserDPInfoModel, int64, error) {
	db := GetDB()
	var infos []VPNAuthUserDPInfoModel
	var total int64

	// 获取总数
	db.Model(&VPNAuthUserDPInfoModel{}).Count(&total)

	// 分页查询
	offset := (page - 1) * pageSize
	res := db.Offset(offset).Limit(pageSize).Find(&infos)
	return infos, total, res.Error
}



// ==================== VPNHostInfoModel 相关操作 ====================

// CreateVPNHostInfo 创建VPN主机信息
func CreateVPNHostInfo(info *proto.VPNHostInfoModel) (*proto.VPNHostInfoModel, error) {
	db := GetDB()
	res := db.Create(info)
	return info, res.Error
}

// GetVPNHostInfoByID 根据ID获取VPN主机信息
func GetVPNHostInfoByID(id uint) (*proto.VPNHostInfoModel, error) {
	db := GetDB()
	var info proto.VPNHostInfoModel
	res := db.Where("id = ?", id).First(&info)
	if res.Error != nil {
		return nil, res.Error
	}
	return &info, nil
}

// GetVPNHostInfoByHostID 根据HostID获取VPN主机信息
func GetVPNHostInfoByHostID(hostID string) (*proto.VPNHostInfoModel, error) {
	db := GetDB()
	var info proto.VPNHostInfoModel
	res := db.Where("host_id = ?", hostID).First(&info)
	if res.Error != nil {
		return nil, res.Error
	}
	return &info, nil
}

// GetVPNHostInfoByHardwareID 根据硬件ID获取VPN主机信息
func GetVPNHostInfoByHardwareID(hardwareID string) (*proto.VPNHostInfoModel, error) {
	db := GetDB()
	var info proto.VPNHostInfoModel
	res := db.Where("hardware_id = ?", hardwareID).First(&info)
	if res.Error != nil {
		return nil, res.Error
	}
	return &info, nil
}

// GetVPNHostInfoByMacAddress 根据MAC地址获取VPN主机信息
func GetVPNHostInfoByMacAddress(macAddress string) ([]proto.VPNHostInfoModel, error) {
	db := GetDB()
	var infos []proto.VPNHostInfoModel
	res := db.Where("mac_address = ?", macAddress).Find(&infos)
	return infos, res.Error
}

// UpdateVPNHostInfo 更新VPN主机信息
func UpdateVPNHostInfo(id uint, info *proto.VPNHostInfoModel) error {
	db := GetDB()
	res := db.Model(&proto.VPNHostInfoModel{}).Where("id = ?", id).Updates(info)
	return res.Error
}

// UpdateVPNHostInfoByHostID 根据HostID更新VPN主机信息
func UpdateVPNHostInfoByHostID(hostID string, info *proto.VPNHostInfoModel) error {
	db := GetDB()
	res := db.Model(&proto.VPNHostInfoModel{}).Where("host_id = ?", hostID).Updates(info)
	return res.Error
}

// UpsertVPNHostInfoByHostID 根据HostID存在则更新，不存在则创建
func UpsertVPNHostInfoByHostID(info *proto.VPNHostInfoModel) (*proto.VPNHostInfoModel, error) {
	db := GetDB()
	var existing proto.VPNHostInfoModel
	res := db.Where("host_id = ?", info.HostID).First(&existing)
	if res.Error != nil {
		// 不存在则创建
		if err := db.Create(info).Error; err != nil {
			return nil, err
		}
		return info, nil
	}
	// 存在则更新
	if err := db.Model(&existing).Updates(info).Error; err != nil {
		return nil, err
	}
	return &existing, nil
}

// DeleteVPNHostInfoByID 根据ID删除VPN主机信息
func DeleteVPNHostInfoByID(id uint) error {
	db := GetDB()
	res := db.Where("id = ?", id).Delete(&proto.VPNHostInfoModel{})
	return res.Error
}

// DeleteVPNHostInfoByHostID 根据HostID删除VPN主机信息
func DeleteVPNHostInfoByHostID(hostID string) error {
	db := GetDB()
	res := db.Where("host_id = ?", hostID).Delete(&proto.VPNHostInfoModel{})
	return res.Error
}

// ListVPNHostInfo 分页获取VPN主机信息
func ListVPNHostInfo(page, pageSize int) ([]proto.VPNHostInfoModel, int64, error) {
	db := GetDB()
	var infos []proto.VPNHostInfoModel
	var total int64

	// 获取总数
	db.Model(&proto.VPNHostInfoModel{}).Count(&total)

	// 分页查询
	offset := (page - 1) * pageSize
	res := db.Order("created_at desc").Offset(offset).Limit(pageSize).Find(&infos)
	return infos, total, res.Error
}