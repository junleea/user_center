package dao

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gorm.io/gorm"
	"log"
	"user_center/proto"
)

type User struct {
	gorm.Model
	Name       string `gorm:"column:name"`
	Age        int    `gorm:"column:age"`
	Email      string `gorm:"column:email"`
	Password   string `gorm:"column:password"`
	Gender     string `gorm:"column:gender"`
	Role       string `gorm:"column:role"`
	Redis      bool   `gorm:"column:redis"`
	Run        bool   `gorm:"column:run"`
	Upload     bool   `gorm:"column:upload"`
	VideoFunc  bool   `gorm:"column:video_func"`  //视频功能
	DeviceFunc bool   `gorm:"column:device_func"` //设备功能
	CIDFunc    bool   `gorm:"column:cid_func"`    //持续集成功能
	Avatar     string `gorm:"column:avatar"`
	CreateTime string `gorm:"column:create_time"`
	QQ         int64  `gorm:"column:qq"`
	QQOpenID   string `gorm:"column:qq_openid"`
	UpdateTime string `gorm:"column:update_time"`
}

// 存储第三方统一信息
type ThirdPartyUserInfo struct {
	gorm.Model
	UserID               int    `json:"user_id"`                 // 用户ID,本系统的用户id
	ThirdPartyID         string `json:"third_party_id"`          // 第三方用户ID
	ThirdPartyEmail      string `json:"third_party_email"`       // 第三方平台用户邮箱
	ThirdPartyPlatform   string `json:"third_party_platform"`    // 第三方平台名称,qq,github
	ThirdPartyUserName   string `json:"third_party_user_name"`   // 第三方用户名
	ThirdPartyUserAvatar string `json:"third_party_user_avatar"` // 第三方用户头像
	ThirdPartyUserUrl    string `json:"third_party_user_url"`    // 第三方用户主页,可选
}

func CreateUser(name, password, email, gender string, age int) uint {
	user := User{Name: name, Email: email, Password: password, Gender: gender, Age: age}
	res := DB.Create(&user)
	if res.Error != nil {
		return 0
	}
	return user.ID
}

func DeleteUserByID(id int) int {
	res := DB.Delete(&User{}, id)
	if res.Error != nil {
		return 0
	}
	return id
}

func FindUserByID(id int) []User {
	var users []User
	//不查询密码
	DB.Where("id = ?", id).First(&users)
	return users
}
func FindUserByID2(id int) User {
	var user User
	DB.Where("id = ?", id).First(&user)
	return user
}

func FindUserByUserID(id int) User {
	var user User
	DB.Where("id = ?", id).First(&user)
	return user
}

func FindUserByName(name string) User {
	var user User
	fmt.Println("name:", name)
	DB.Where("name = ?", name).First(&user)
	return user
}

// 根据name模糊查询，邮箱也是,不查询密码
func FindUserByNameLike(name string) []User {
	var users []User
	DB.Where("name LIKE ? OR email LIKE ?", "%"+name+"%", "%"+name+"%").Find(&users).Limit(32)
	return users
}

func FindUserByEmail(email string) User {
	var user User
	DB.Where("email = ?", email).First(&user)
	return user
}

func UpdateUserByID(id int, name, password, email string) {
	DB.Model(&User{}).Where("id = ?", id).Updates(User{Name: name, Password: password, Email: email})
}

// 管理员修改用户信息
func UpdateUserByID2(id int, req proto.UpdateUserInfoReq) error {
	updateData := make(map[string]interface{})
	updateData["Name"] = req.Username
	updateData["Age"] = req.Age
	updateData["Role"] = req.Role
	updateData["Run"] = req.Run
	updateData["Redis"] = req.Redis
	updateData["Upload"] = req.Upload
	updateData["VideoFunc"] = req.VideoFunc
	updateData["DeviceFunc"] = req.DeviceFunc
	updateData["CIDFunc"] = req.CIDFunc
	updateData["Avatar"] = req.Avatar
	updateData["Gender"] = req.Gender
	updateData["QQ"] = req.QQ
	res := DB.Model(&User{}).Where("id =?", id).Updates(updateData)
	if res.Error != nil {
		return res.Error
	}
	return nil
}

// 用户修改自己的信息
func UpdateUserByID3(id int, req proto.UpdateUserInfoReq) error {
	res := DB.Model(&User{}).Where("id = ?", id).Updates(User{Name: req.Username, Age: req.Age, Avatar: req.Avatar, Gender: req.Gender, QQ: req.QQ})
	return res.Error
}

// 用户数据同步-添加
func AddUserSync(req proto.UserAddOrUpdate) uint {
	res := DB.Exec("insert into users (id, created_at, updated_at, deleted_at, name, age, email, password,gender,role,redis,run,upload,video_func,device_func,cid_func,avatar,create_time,update_time) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", req.ID, req.CreatedAt, req.UpdatedAt, req.DeletedAt, req.Name, req.Age, req.Email, req.Password, req.Gender, req.Role, req.Redis, req.Run, req.Upload, req.VideoFunc, req.DeviceFunc, req.CIDFunc, req.Avatar, req.CreateTime, req.UpdateTime)
	if res.Error != nil {
		return 0
	}
	res = DB.Debug().Exec("update users set deleted_at=null where id=?", req.ID)
	if res.Error != nil {
		return 0
	}
	return req.ID
}

// 用户数据同步-更新
func UpdateUserSync(req proto.UserAddOrUpdate) uint {
	//事务
	res := DB.Exec("update users set created_at=?, updated_at=?, deleted_at=?, name=?, age=?, email=?, password=?,gender=?,role=?,redis=?,run=?,upload=?,video_func=?,device_func=?,cid_func=?,avatar=?,create_time=?,update_time=? where id=?", req.CreatedAt, req.UpdatedAt, req.DeletedAt, req.Name, req.Age, req.Email, req.Password, req.Gender, req.Role, req.Redis, req.Run, req.Upload, req.VideoFunc, req.DeviceFunc, req.CIDFunc, req.Avatar, req.CreateTime, req.UpdateTime, req.ID)
	if res.Error != nil {
		return 0
	}
	res = DB.Debug().Exec("update users set deleted_at=null where id=?", req.ID)
	if res.Error != nil {
		return 0
	}
	return req.ID
}

// 用户数据同步-删除
func DeleteUserSync(req proto.UserDelID) uint {
	res := DB.Delete(&User{}, req.ID)
	if res.Error != nil {
		return 0
	}
	return req.ID
}

// 获取所有用户
func GetAllUser() []User {
	var users []User
	DB.Find(&users)
	return users
}

// 用户数据同步
type UserSyncResp struct {
	Update []User            `json:"update" form:"update"` //更新用户
	Add    []User            `json:"add" form:"add"`       //添加用户
	Delete []proto.UserDelID `json:"delete" form:"delete"` //删除用户
}

// 清空用户表
func ClearAllUsers() error {
	res := DB.Exec("TRUNCATE TABLE users")
	return res.Error
}

// 获取前20个用户
func FindUsersDefault() []User {
	var users []User
	DB.Limit(20).Find(&users)
	return users
}

// 用户的信息统计数据
type UserStatistics struct {
	SessionCount int64 `json:"session_count" form:"session_count"` //会话数量
	FileCount    int64 `json:"file_count" form:"file_count"`       //文件数量
	MessageCount int64 `json:"message_count" form:"message_count"` //消息数量,提问数量
}

func FindUserNum() int64 {
	var count int64
	DB.Model(&User{}).Count(&count)
	return count
}

// 根据用户id获取第三方平台信息
func FindThirdPartyUserInfoByUserID(userID int) []ThirdPartyUserInfo {
	var thirdPartyUserInfos []ThirdPartyUserInfo
	res := DB.Where("user_id = ?", userID).Find(&thirdPartyUserInfos)
	if res.Error != nil {
		log.Println("FindThirdPartyUserInfoByUserID error:", res.Error, "\tuserID:", userID)
	}
	return thirdPartyUserInfos
}

// 根据平台用户id获取信息
func FindThirdPartyUserInfoByThirdPartyID(thirdPartyID string) []ThirdPartyUserInfo {
	var thirdPartyUserInfo []ThirdPartyUserInfo
	res := DB.Where("third_party_id = ?", thirdPartyID).First(&thirdPartyUserInfo)
	if res.Error != nil {
		log.Println("FindThirdPartyUserInfoByThirdPartyID error:", res.Error, "\tthirdPartyID:", thirdPartyID)
	}
	return thirdPartyUserInfo
}

// 根据第三方平台名称和用户id获取信息
func FindThirdPartyUserInfoByPlatformAndUserID(thirdPartyPlatform string, userID int) []ThirdPartyUserInfo {
	var thirdPartyUserInfo []ThirdPartyUserInfo
	DB.Where("third_party_platform = ? and user_id = ?", thirdPartyPlatform, userID).First(&thirdPartyUserInfo)
	return thirdPartyUserInfo
}

func CreateThirdPartyUserInfo(userID int, thirdPartyID, thirdPartyPlatform, thirdPartyUserName, thirdPartyUserAvatar, thirdPartyUserUrl string) uint {
	thirdPartyUserInfo := ThirdPartyUserInfo{UserID: userID, ThirdPartyID: thirdPartyID, ThirdPartyPlatform: thirdPartyPlatform, ThirdPartyUserName: thirdPartyUserName, ThirdPartyUserAvatar: thirdPartyUserAvatar, ThirdPartyUserUrl: thirdPartyUserUrl}
	res := DB.Create(&thirdPartyUserInfo)
	if res.Error != nil {
		return 0
	}
	return thirdPartyUserInfo.ID
}
func CreateThirdPartyUserInfoV2(thirdPartyUserInfo *ThirdPartyUserInfo) uint {
	db2 := DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	}
	res := db2.Create(thirdPartyUserInfo)
	if res.Error != nil {
		return 0
	}
	return thirdPartyUserInfo.ID
}

// 删除
func DeleteThirdPartyUserInfoByID(id int) int {
	res := DB.Delete(&ThirdPartyUserInfo{}, id)
	if res.Error != nil {
		return 0
	}
	return id
}

func DeleteThirdPartyLoginByID(id int, userID int) error {
	res := DB.Where("id = ? and user_id = ?", id, userID).Delete(&ThirdPartyUserInfo{})
	if res.Error != nil {
		return res.Error
	}
	return nil
}

// 更新第三方登录用户信息
func UpdateThirdPartyUserInfoByThirdPartyID(thirdPartyID, thirdPartyPlatform, thirdPartyUserName, thirdPartyUserAvatar, thirdPartyUserUrl string) error {
	db2 := DB
	if proto.Config.SERVER_SQL_LOG {
		db2 = DB.Debug()
	}

	res := db2.Model(&ThirdPartyUserInfo{}).Where("third_party_id = ? ", thirdPartyID).Updates(ThirdPartyUserInfo{ThirdPartyUserName: thirdPartyUserName, ThirdPartyUserAvatar: thirdPartyUserAvatar, ThirdPartyUserUrl: thirdPartyUserUrl, ThirdPartyPlatform: thirdPartyPlatform})
	if res.Error != nil {
		return res.Error
	}
	return nil
}

/***************************************mongodb*****************************************/
const UserUIConfigCollection = "user_ui_config"

// 用户对前端的配置信息
func CreateUserUIConfigInfo(config proto.UserUIConfigInfo) (string, error) {
	collection := mongoClient.Database(proto.Config.MONGO_DATABASE).Collection(UserUIConfigCollection)
	res, err := collection.InsertOne(context.TODO(), config)
	if err != nil {
		fmt.Println("Error inserting document:", err)
		return "", err
	}
	fmt.Println("Inserted a single document:", res.InsertedID)
	// 类型安全转换
	insertedID, ok := res.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.NilObjectID.String(), fmt.Errorf("意外的ID类型: %T", res.InsertedID)
	}
	return insertedID.String(), nil
}

func GetUserUIConfigInfo(userID int) (proto.UserUIConfigInfo, error) {
	//log.Println("get user ui config info database:", proto.Config.MONGO_DATABASE, " collection:", UserUIConfigCollection)
	collection := mongoClient.Database(proto.Config.MONGO_DATABASE).Collection(UserUIConfigCollection)
	var config proto.UserUIConfigInfo
	err := collection.FindOne(context.TODO(), bson.M{"user_id": userID}).Decode(&config)
	if err != nil {
		fmt.Println("Error finding document:", err)
		return config, err
	}
	return config, nil
}

func UpdateUserUIConfigInfo(userID int, config proto.UserUIConfigInfo) error {
	collection := mongoClient.Database(proto.Config.MONGO_DATABASE).Collection(UserUIConfigCollection)
	filter := bson.M{"user_id": userID}
	update := bson.M{"$set": config}
	_, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		fmt.Println("Error updating document:", err)
		return err
	}
	return nil
}

func DeleteUserUIConfigInfo(userID int) error {
	collection := mongoClient.Database(proto.Config.MONGO_DATABASE).Collection(UserUIConfigCollection)
	filter := bson.M{"user_id": userID}
	_, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		fmt.Println("Error deleting document:", err)
		return err
	}
	return nil
}

// 根据用户id数组获取用户基础信息
func FindBaseUserInfoByIDs(ids []int) []proto.BaseUserInfo {
	var res []proto.BaseUserInfo
	var db *gorm.DB
	if proto.Config.SERVER_SQL_LOG {
		db = DB.Debug()
	} else {
		db = DB
	}
	err := db.Find(&res, "id in ?", ids).Limit(1000)
	if err.Error != nil {
		log.Println("FindBaseUserInfoByIDs error:", err.Error, "ids:", ids)
		return res
	}
	return res
}
