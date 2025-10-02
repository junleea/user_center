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

func RunSQLWithOrder(sql string) (result proto.SQLResult, err error) {
	var db2 *gorm.DB
	// 保留 Debug 模式
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB
	} else {
		db2 = DB
	}

	// 执行 SQL 并获取底层 Rows 对象
	rows, err := db2.Raw(sql).Rows()
	if err != nil {
		return result, err
	}
	defer rows.Close() // 确保关闭 Rows

	// 获取列名顺序（关键：这里的顺序与 SQL 查询的列顺序一致）
	columns, err := rows.Columns()
	if err != nil {
		return result, err
	}
	for _, col := range columns {
		result.Columns = append(result.Columns, proto.SQLResultColumnsValue{Prop: col, Label: col})
	}

	// 遍历每行数据
	for rows.Next() {
		// 准备接收每行数据的容器（按列顺序）
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns)) // 用于 Scan 的指针切片

		// 为每个列绑定指针（Scan 要求传入指针）
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// 扫描当前行数据到指针切片
		if err2 := rows.Scan(valuePtrs...); err2 != nil {
			return result, err2
		}

		// 将当前行数据存入 map（便于按列名访问）
		rowMap := make(map[string]interface{})
		for i, col := range columns {
			rowMap[col] = values[i]
		}
		result.Rows = append(result.Rows, rowMap)
	}

	// 检查遍历过程中是否有错误
	if err = rows.Err(); err != nil {
		return result, err
	}

	return result, nil
}
