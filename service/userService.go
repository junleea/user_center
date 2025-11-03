package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"log"
	"regexp"
	"strconv"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker"
)

func CreateUser(name, password, email, gender string, age int) uint {
	id := dao.CreateUser(name, password, email, gender, age)
	if id != 0 {
		//添加用户信息到同步列表
		err := setSyncUserDataSet("add", int(id))
		if err != nil {
			return id
		}
	}
	return id
}

func GetUser(name, email, password string) dao.User {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	var user dao.User
	if re.MatchString(name) {
		user = dao.FindUserByEmail(name)
	} else {
		user = dao.FindUserByName(name)
	}
	if user.ID != 0 && user.Password == password {
		return user
	}
	return dao.User{}
}

func ContainsUser(name, email string) bool {
	user := dao.FindUserByName(name)
	user2 := dao.FindUserByEmail(email)
	if user.ID != 0 || user2.ID != 0 {
		return true
	}
	return false
}

func GetUserByID(id int) []dao.User {
	users := dao.FindUserByID(id)
	for i, _ := range users {
		users[i].Password = "" //不返回密码
	}
	return users
}

// 获取用户信息，有redis缓存
func GetUserByIDWithCache(id int) dao.User {
	if id <= 0 {
		return dao.User{}
	}
	var user dao.User
	//先从redis获取
	key := "user_info_" + strconv.Itoa(id)
	user_str := worker.GetRedis(key)
	if user_str != "" {
		err := json.Unmarshal([]byte(user_str), &user)
		if err != nil {
			fmt.Println("get user info , json unmarshal error:", err, "\tuser_str:", user_str)
		}
	} else {
		user = dao.FindUserByID2(id)
		if user.ID != 0 {
			userJson, err := json.Marshal(user)
			if err != nil {
				fmt.Println("get user info , json marshal error:", err)
				return dao.User{}
			}
			success := worker.SetRedis(key, string(userJson))
			if !success {
				fmt.Println("set redis error,user json:", string(userJson))
			}
		}
	}
	return user
}

func GetUserByNameLike(name string) []dao.User {
	users := dao.FindUserByNameLike(name)
	for i, _ := range users {
		users[i].Password = ""
	}
	return users
}

// 获取默认前20个用户
func GetUsersDefault() []dao.User {
	users := dao.FindUsersDefault()
	for i, _ := range users {
		users[i].Password = ""
	}
	return users
}

func setUpdateReq(user *dao.User, req *proto.UpdateUserInfoReq) {
	if req.Username == "" {
		req.Username = user.Name
	}
	if req.Run == 0 {
		req.Run = user.Run
	}
	if req.Redis == 0 {
		req.Redis = user.Redis
	}
	if req.Role == "" {
		req.Role = user.Role
	}
	if req.Age == 0 {
		req.Age = user.Age
	}
	if req.Avatar == "" {
		req.Avatar = user.Avatar
	}
	if req.CIDFunc == 0 {
		req.CIDFunc = user.CIDFunc
	}
	if req.VideoFunc == 0 {
		req.VideoFunc = user.VideoFunc
	}
	if req.DeviceFunc == 0 {
		req.DeviceFunc = user.DeviceFunc
	}
	if req.Upload == 0 {
		req.Upload = user.Upload
	}
	if req.Gender == "" {
		req.Gender = user.Gender
	}

	if req.PasswordNeedSecondAuth == 0 {
		req.PasswordNeedSecondAuth = user.PasswordNeedSecondAuth
	}
	if req.CodeNeedSecondAuth == 0 {
		req.CodeNeedSecondAuth = user.CodeNeedSecondAuth
	}
	if req.ThirdPartyNeedSecondAuth == 0 {
		req.ThirdPartyNeedSecondAuth = user.ThirdPartyNeedSecondAuth
	}
	if req.AISecondAuth == 0 {
		req.AISecondAuth = user.AISecondAuth
	}

}

func UpdateUser(user_id int, req proto.UpdateUserInfoReq) (int, error) {
	cur_user := dao.FindUserByID2(user_id)
	//fmt.Println("cur_user:", cur_user, "req:", req)
	if user_id == req.ID && cur_user.Role != "admin" {
		setUpdateReq(&cur_user, &req)
		err := dao.UpdateUserByID3(user_id, req) //用户修改自己的信息，不能修改权限信息
		//添加修改用户信息到同步列表
		if err == nil {
			err2 := setSyncUserDataSet("update", user_id)
			UpdateUserCache(user_id)
			if err2 != nil {
				fmt.Println("set sync user data set error:", err2)
				return user_id, nil
			}
		}
		return user_id, err
	} else if cur_user.Role == "admin" {
		user := dao.FindUserByID(req.ID)[0]
		setUpdateReq(&user, &req)
		err := dao.UpdateUserByID2(req.ID, req)
		if err == nil {
			//添加修改用户信息到同步列表
			err2 := setSyncUserDataSet("update", req.ID)
			UpdateUserCache(req.ID)
			if err2 != nil {
				fmt.Println("set sync user data set error:", err2)
				return req.ID, nil
			}
		}
		return req.ID, nil
	} else {
		return 0, nil
	}
}

func UpdateUserCache(id int) {
	key := "user_info_" + strconv.Itoa(id)
	if worker.IsContainKey(key) {
		user := dao.FindUserByID2(id)
		userJson, err := json.Marshal(user)
		if err != nil {
			fmt.Println("get user info , json marshal error:", err)
		}
		worker.SetKVWithExpire(key, string(userJson), time.Second*10)
	}
}

func DeleteUserService(id, user_id int) int {
	res := 0
	if user_id == id {
		res = dao.DeleteUserByID(id)
	} else {
		user := dao.FindUserByID2(user_id)
		if user.Role == "admin" {
			res = dao.DeleteUserByID(id)
		}
	}
	if res != 0 {
		//添加删除用户信息到同步列表
		err := setSyncUserDataSet("delete", id)
		if err != nil {
			return res
		}
	}
	return res
}

// 同步数据到主服务器-增删改数据
func GetUserSyncData(device string) dao.UserSyncResp {
	key := device + "_sync_user_ids"
	add_temp_key := device + "_sync_user_ids_add_confirm_temp"
	update_temp_key := device + "_sync_user_ids_update_confirm_temp"
	delete_temp_key := device + "_sync_user_ids_delete_confirm_temp"
	//需要获取暂存集合的并集，清空暂存集合，存入待确认集合
	add_user_ids := worker.GetRedisSetUnion(key+"_add", add_temp_key)
	update_user_ids := worker.GetRedisSetUnion(key+"_update", update_temp_key)
	delete_user_ids := worker.GetRedisSetUnion(key+"_delete", delete_temp_key)
	add_users := []dao.User{}
	update_users := []dao.User{}
	delete_users := []proto.UserDelID{}
	for _, v := range add_user_ids {
		id, _ := strconv.Atoi(v)
		user := dao.FindUserByUserID(id)
		add_users = append(add_users, user)
	}

	for _, v := range update_user_ids {
		id, _ := strconv.Atoi(v)
		user := dao.FindUserByUserID(id)
		update_users = append(update_users, user)
	}

	for _, v := range delete_user_ids {
		id, _ := strconv.Atoi(v)
		delete_users = append(delete_users, proto.UserDelID{ID: uint(id)})
	}
	//将id存入暂存集合，清空原集合，存入待确认集合主要保证在确认时，有新的数据加入不会在确认时漏掉
	worker.SetRedisSetUnionAndStore(add_temp_key, key+"_add")
	worker.ClearRedisSet(key + "_add")
	worker.SetRedisSetUnionAndStore(update_temp_key, key+"_update")
	worker.ClearRedisSet(key + "_update")
	worker.SetRedisSetUnionAndStore(delete_temp_key, key+"_delete")
	worker.ClearRedisSet(key + "_delete")
	return dao.UserSyncResp{Add: add_users, Update: update_users, Delete: delete_users}
}

func FindBaseUserInfoList(ids []int) []proto.BaseUserInfo {
	return dao.FindBaseUserInfoByIDs(ids)
}

func setSyncUserDataSet(t string, id int) error {
	devices := worker.GetRedisSetMembers("sync_devices_ids") //主服务器查看从服务器的设备列表
	fmt.Println("set sync user data set devices:", devices, "t:", t, "id:", id)
	var err error
	for _, device := range devices {
		key := device + "_sync_user_ids"
		if t == "add" {
			key_ := key + "_add"
			worker.SetRedisSetAdd(key_, strconv.Itoa(id))
		} else if t == "update" {
			key_ := key + "_update"
			worker.SetRedisSetAdd(key_, strconv.Itoa(id))
		} else if t == "delete" {
			key_ := key + "_delete"
			worker.SetRedisSetAdd(key_, strconv.Itoa(id))
		} else {
			err = errors.New("error")
		}
	}
	return err
}

// 生成新的token，存入redis，返回信息
func CreateTokenAndSave(user dao.User) (string, error) {
	var tokenString string
	var err error
	key := "user_" + user.Name
	redis_token := worker.GetRedis(string(key))
	if redis_token == "" {
		// 生成 JWT 令牌
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": user.Name,
			"id":       user.ID,
			"exp":      time.Now().Add(time.Hour * 10).Unix(), // 令牌过期时间, 10小时后过期
		})
		tokenString, err = token.SignedString(proto.SigningKey)
		if err != nil {
			return "", err
		}

		worker.SetRedisWithExpire("user_"+user.Name, tokenString, time.Hour*10) // 将用户信息存入
		worker.SetRedisWithExpire(tokenString, tokenString, time.Hour*10)       // 设置过期时间为10分钟
		data := make(map[string]interface{})
		data["id"] = user.ID
		data["username"] = user.Name
		data["email"] = user.Email
		worker.SetHash(tokenString, data) // 将用户信息存入
	} else {
		tokenString = redis_token
	}
	// 返回令牌
	return tokenString, err
}

func CalculateUserTokenAndSetCache(user dao.User) (string, error) {
	// 生成 JWT 令牌
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"username": user.Name,
		"id":       user.ID,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // 令牌过期时间, 24小时后过期
	})
	tokenString, err := token.SignedString(proto.SigningKey)
	//设置缓存
	worker.SetRedisWithExpire("user_"+user.Name, tokenString, time.Hour*24) // 将用户信息存入
	worker.SetRedisWithExpire(tokenString, tokenString, time.Hour*24)       // 设置过期时间为24小时

	return tokenString, err
}

// GenerateAuthTokens creates new access and refresh tokens for a user
func GenerateAuthTokens(user dao.User) (accessTokenString string, refreshTokenString string, err error) {
	// Generate Access Token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Name,
		"id":       user.ID,
		"type":     "access",
		"exp":      time.Now().Add(proto.AccessTokenDuration).Unix(),
	})
	accessTokenString, err = accessToken.SignedString(proto.SigningKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate Refresh Token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   user.ID,
		"type": "refresh",
		"exp":  time.Now().Add(proto.RefreshTokenDuration).Unix(),
	})
	refreshTokenString, err = refreshToken.SignedString(proto.SigningKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	// Store Refresh Token in Redis
	redisKey := fmt.Sprintf("refresh_token:%d:%s", user.ID, refreshTokenString)
	if !worker.SetRedisWithExpire(redisKey, "active", proto.RefreshTokenDuration) { // Value can be simple, e.g., "active" or user.ID
		return "", "", fmt.Errorf("failed to store refresh token in Redis")
	}

	return accessTokenString, refreshTokenString, nil
}

func GetUserInfoByToken(token string) (dao.User, error) {
	//解析token
	claims := jwt.MapClaims{}
	var user dao.User
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return proto.SigningKey, nil
	})
	if err != nil {
		return user, err
	}
	if !tkn.Valid {
		return user, errors.New("token is invalid")
	}
	id := int(claims["id"].(float64))
	user = GetUserByIDWithCache(id)
	if user.ID == 0 {
		return user, errors.New("user not found")
	}
	user.Password = "" // Ensure password is not returned
	return user, nil
}

// ValidateRefreshTokenAndCreateNewAccessToken validates a refresh token and generates a new access token.
func ValidateRefreshTokenAndCreateNewAccessToken(refreshTokenString string) (newAccessTokenString string, err error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(refreshTokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Make sure that the token's signing method is what you expect.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return proto.SigningKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to parse refresh token: %w", err)
	}

	if !token.Valid {
		return "", errors.New("refresh token is invalid")
	}

	userIDFloat, ok := claims["id"].(float64)
	if !ok {
		return "", errors.New("invalid user ID in refresh token claims")
	}
	userID := uint(userIDFloat) // Assuming user ID in token is of type uint

	// Check if the refresh token exists in Redis
	redisKey := fmt.Sprintf("refresh_token:%d:%s", userID, refreshTokenString)
	if !worker.IsContainKey(redisKey) {
		return "", errors.New("refresh token not found in Redis or has expired")
	}

	// Fetch user details
	user := dao.FindUserByID2(int(userID)) // Assuming FindUserByID2 takes int
	if user.ID == 0 {
		return "", errors.New("user not found")
	}

	// Generate a new access token
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Name,
		"id":       user.ID,
		"type":     "access",
		"exp":      time.Now().Add(proto.AccessTokenDuration).Unix(),
	})

	newAccessTokenString, err = newAccessToken.SignedString(proto.SigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign new access token: %w", err)
	}

	return newAccessTokenString, nil
}

// 获取用户前端配置信息
func GetUserUIConfigInfo(userID int) proto.UserUIConfigInfo {
	userConfig, err := dao.GetUserUIConfigInfo(userID)
	if err != nil {
		userConfig.UserID = userID
		//没有则插入
		id, err2 := dao.CreateUserUIConfigInfo(userConfig)
		if err2 != nil {
			log.Println("InsertUserUIConfigInfo error:", err.Error())
		} else {
			log.Println("InsertUserUIConfigInfo success, id:", id, "config:", userConfig)
		}
	}
	userConfig, err = dao.GetUserUIConfigInfo(userID)
	return userConfig
}

// 设置用户前端配置信息
func SetUserUIConfigInfo(userID int, config proto.UserUIConfigInfo) error {
	//先查询是否有该用户的配置信息
	userConfig, err := dao.GetUserUIConfigInfo(userID)
	if err != nil {
		log.Println("SetUserUIConfigInfo error:", err)
	}
	config.UserID = userID
	if userConfig.UserID == 0 {
		//没有则插入
		id, err2 := dao.CreateUserUIConfigInfo(config)
		if err2 != nil {
			log.Println("InsertUserUIConfigInfo error:", err.Error())
			return err
		} else {
			log.Println("InsertUserUIConfigInfo success, id:", id, "config:", config)
		}
	} else {
		//有则更新
		err3 := dao.UpdateUserUIConfigInfo(userID, config)
		if err3 != nil {
			log.Println("UpdateUserUIConfigInfo error:", err)
			return err
		}
	}
	return nil
}

func SendLoginCodeByEmailPhone(req proto.EmailPhoneCodeLoginReq) error {
	var state proto.SecondAuthServerSaveState
	if req.State != "" {
		state_str := worker.GetKV(req.State)
		if state_str == "" {
			return errors.New("二次认证状态错误")
		} else {
			_ = json.Unmarshal([]byte(state_str), &state)
			user := GetUserByIDWithCache(state.UserId)
			req.Email = user.Email
		}
	}
	var res error
	//邮件
	if req.LoginType == 1 {
		if req.Email == "" {
			return errors.New("invalid email")
		}
		user := dao.FindUserByEmail(req.Email)
		if user.ID == 0 {
			res = errors.New("用户不存在，请先注册！")
		} else {
			key := "login_code_" + req.Email
			if worker.IsContainKey(key + "_") {
				//存在说明发过验证码，返回错误
				res = errors.New("发送过于频繁，请稍后再试！")
			} else {
				//随机字符串验证码大写
				code := worker.GetRandomString(6)
				if state.UserId > 0 {
					state.Code = code
					stateBytes, _ := json.Marshal(state)
					worker.SetKV(req.State, string(stateBytes)) //二次认证允许时间
				}
				worker.SetRedisWithExpire(key, code, time.Minute*5) //设置5分钟过期
				//发送邮件
				//go SendEmail(req.Email, "集成AI工具邮件验证码", "登录验证码:"+code+" ,请在5分钟内使用!")
				go SendEmailCodeMail(req.Email, code, "登录")
				worker.SetRedisWithExpire(key+"_", code, time.Minute*1) //每分钟只能发一次
			}
		}
	} else if req.LoginType == 2 {
		//电话号码
		res = errors.New("不支持短信验证，无法发送验证码")
	} else {
		res = errors.New("无效的验证码方式")
	}
	return res
}

// 查看用户是否能使用用户名密码,需使用验证码登录
func CheckUserCanUsePassword(user *dao.User, hostId, ip string) (bool, string) {
	var deviceInfo []proto.UserLoginDeviceInfo
	var addressInfo []proto.UserLoginAddressInfo
	err := json.Unmarshal([]byte(user.LoginDeviceInfo), &deviceInfo)
	log.Println("check user id:", user.ID, "\t host_id:", hostId, "\t ip:", ip)
	if err != nil {
		log.Println("CheckUserCanUsePassword address info, error:", err)
		return false, "校验设备错误"
	}
	err = json.Unmarshal([]byte(user.LoginAddressInfo), &addressInfo)
	if err != nil {
		log.Println("CheckUserCanUsePassword address info, error:", err)
		return false, "校验地址错误"
	}
	address := GetIPRegionByAPI(ip)
	//log.Println("check  user id", user.ID, "req address info:", address, ", host id:", hostId, ", address info:", addressInfo)
	var currentDeviceInfo proto.UserLoginDeviceInfo
	var currentAddressInfo proto.UserLoginAddressInfo
	var reason string
	for i, v := range addressInfo {
		if v.Address == address {
			currentAddressInfo = addressInfo[i]
		}
	}
	for i, v := range deviceInfo {
		if v.HostID == hostId {
			currentDeviceInfo = deviceInfo[i]
		}
	}
	//是否是首次登录设备
	if currentDeviceInfo.HostID == "" {
		reason = "首次登录设备"
		return false, reason //首次登录设备，不能密码
	}

	//是否是首次登录地点
	if currentAddressInfo.Address == "" {
		reason = "首次登录地点：" + address
		return false, reason //首次登录地点，不能使用密码
	}
	now := time.Now().Unix()
	var time_ int64
	time_ = 14 * 24 * 60 * 60
	//是否过长时间未登录设备14天
	if (now - currentDeviceInfo.LastLogin) > time_ {
		reason = "设备长时间未登录"
		return false, reason
	}

	//是否过长时间未登录地点14天
	if (now - currentAddressInfo.LastLogin) > time_ {
		reason = "地点长时间未登录"
		return false, reason
	}
	return true, ""
}

// 更新用户登录设备、地址信息
func UpdateUserLoginAddressDeviceInfo(user *dao.User, hostID, ip string) {
	var deviceInfo []proto.UserLoginDeviceInfo
	var addressInfo []proto.UserLoginAddressInfo
	err := json.Unmarshal([]byte(user.LoginDeviceInfo), &deviceInfo)
	if err != nil {
		log.Println("Update User Login Device Info, error:", err)
	}
	err = json.Unmarshal([]byte(user.LoginAddressInfo), &addressInfo)
	if err != nil {
		log.Println("Update User Login address info, error:", err)
	}
	log.Println("user id:", user.ID, "\t host_id:", hostID, "\t ip:", ip)
	//更新设备信息
	index := -1
	for i, v := range deviceInfo {
		if v.HostID == hostID {
			index = i
		}
	}
	now := time.Now().Unix()
	if index == -1 {
		device := proto.UserLoginDeviceInfo{
			HostID:     hostID,
			FirstLogin: now,
			LastLogin:  now,
			LoginCount: 1,
		}
		deviceInfo = append(deviceInfo, device)
	} else {
		deviceInfo[index].LoginCount++
		deviceInfo[index].LastLogin = now
	}
	deviceInfoStr, _ := json.Marshal(deviceInfo)
	//更新地址信息
	index = -1
	address := GetIPRegionByAPI(ip)
	for i, v := range addressInfo {
		if v.Address == address {
			index = i
		}
	}

	if index == -1 {
		address_ := proto.UserLoginAddressInfo{
			IPAddress:  ip,
			Address:    address,
			FirstLogin: now,
			LastLogin:  now,
			LoginCount: 1,
		}
		addressInfo = append(addressInfo, address_)
	} else {
		addressInfo[index].LoginCount++
		addressInfo[index].LastLogin = now
	}
	addressInfoStr, _ := json.Marshal(addressInfo)
	err = dao.UpdateUserLoginAddressAndDeviceInfo(int(user.ID), string(deviceInfoStr), string(addressInfoStr))
	if err != nil {
		log.Println("update user login device and address info error:", err)
	}
	UpdateUserCache(int(user.ID)) //更新缓存
}

func GetUserTOTPSecretInfo(user *dao.User) *dao.TOTPSecretInfo {
	totp_secret_info := dao.FindUserTOTPSecretByUserID(user.ID)
	if totp_secret_info.ID != 0 {
		totp_secret_info.Secret = ""
	}
	return &totp_secret_info
}

func CheckAndGenerateTOTPSecret(user *dao.User) (*proto.GenAndGetTOTPSecretResponse, error) {
	resp := &proto.GenAndGetTOTPSecretResponse{}
	//查看是否已有，若已有则不能生成
	totp_secret_info := dao.FindUserTOTPSecretByUserID(user.ID)
	if totp_secret_info.ID != 0 {
		//resp.CreatedAt = totp_secret_info.CreatedAt
		return resp, errors.New("已有密钥，若要创建需先解绑")
	}
	// 生成随机TOTP密钥
	secret_info, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SAW_" + user.Name,
		AccountName: user.Email,
		Algorithm:   proto.TOTP_SECRET_ALGORITHM,
		Digits:      proto.TOTP_CODE_LENGTH,
		Period:      proto.TOTP_PERIOD,
	})
	if err != nil {
		log.Println("generate TOTP secret error:", err)
		return nil, errors.New("创建TOTP密钥失败")
	}

	//创建
	err = dao.InsertUserTOTPSecret(int(user.ID), secret_info.Secret(), proto.OTP_TYPE_TOTP)
	if err != nil {
		log.Println("insert user totp secret error:", err)
		return nil, errors.New("保存TOTP失败")
	}
	resp.Secret, resp.URL = secret_info.Secret(), secret_info.URL()
	return resp, nil
}

func CheckAndGenerateHOTPSecret(user *dao.User) (*proto.GenAndGetTOTPSecretResponse, error) {
	resp := &proto.GenAndGetTOTPSecretResponse{}
	//查看是否已有，若已有则不能生成
	totp_secret_info := dao.FindUserTOTPSecretByUserID(user.ID)
	if totp_secret_info.ID != 0 {
		//resp.CreatedAt = totp_secret_info.CreatedAt
		return resp, errors.New("已有密钥，若要创建需先解绑")
	}
	// 生成随机TOTP密钥
	secret_info, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      "SAW_" + user.Name,
		AccountName: user.Email,
		Algorithm:   proto.TOTP_SECRET_ALGORITHM,
		Digits:      proto.TOTP_CODE_LENGTH,
	})
	if err != nil {
		log.Println("generate TOTP secret error:", err)
		return nil, errors.New("创建TOTP密钥失败")
	}

	//创建
	err = dao.InsertUserTOTPSecret(int(user.ID), secret_info.Secret(), proto.OTP_TYPE_TOTP)
	if err != nil {
		log.Println("insert user totp secret error:", err)
		return nil, errors.New("保存TOTP失败")
	}
	resp.Secret, resp.URL = secret_info.Secret(), secret_info.URL()
	return resp, nil
}

func DelTOTPSecret(user *dao.User, delType int, userID uint) error {
	var err error
	if user.Role == "admin" {
		if delType == 0 {
			//删除自己的，默认
			err = dao.DelUserTOTPSecret(user.ID)
		} else if delType == 1 {
			if userID == 0 {
				err = errors.New("")
			} else {
				//删除指定用户的
				err = dao.DelUserTOTPSecret(userID)
			}
		} else if delType == 2 {
			//删除所有
			err = dao.DelAllUserTOTPSecret()
		} else {
			err = errors.New("错误的操作类型")
		}
	} else {
		err = dao.DelUserTOTPSecret(user.ID)
	}
	return err
}

func CheckUserTOTPCode(user *dao.User, code string) error {
	var err error
	secret_info := dao.FindUserTOTPSecretByUserID(user.ID)
	if secret_info.ID == 0 {
		return errors.New("未绑定TOTP密钥，请先登录绑定！")
	}

	// 验证TOTP验证码
	valid, err := totp.ValidateCustom(
		code,
		secret_info.Secret,
		time.Now(),
		totp.ValidateOpts{
			Algorithm: otp.Algorithm(secret_info.Algorithm),
			Digits:    otp.Digits(secret_info.Length),
			Period:    uint(secret_info.Period),
		},
	)
	if valid == false {
		return errors.New("无效的TOTP验证码")
	}
	return err
}

func CheckUserHOTPCode(user *dao.User, code string) error {
	var err error
	secret_info := dao.FindUserTOTPSecretByUserID(user.ID)
	if secret_info.ID == 0 {
		return errors.New("未绑定TOTP密钥，请先登录绑定！")
	}

	// 验证TOTP验证码
	valid, err := hotp.ValidateCustom(
		code,
		0,
		secret_info.Secret,
		hotp.ValidateOpts{
			Algorithm: otp.Algorithm(secret_info.Algorithm),
			Digits:    otp.Digits(secret_info.Length),
		},
	)
	if valid == false {
		return errors.New("无效的TOTP验证码")
	}
	return err
}

func NeedSecondAuthService(user *dao.User, second_auth_type string) (*proto.NeedSecondAuthResp, error) {
	var resp proto.NeedSecondAuthResp
	//支持认证方式
	user_totp_secret := GetUserTOTPSecretInfo(user)
	if user_totp_secret.ID != 0 {
		//支持totp
		resp.Type += ",TOTP"
	}
	//后续支持其他认证方式添加在下面
	//支持邮件验证码
	if second_auth_type != "code" {
		resp.Type += ",EMAIL"
	}

	if resp.Type == "" {
		log.Println("[error] admin config need second auth but the user not support any second auth type!")
		return nil, errors.New("类型不支持，二次认证配置不支持")
	}
	var uuidStr string //state信息
	uuid_ := uuid.New()
	uuidStr = uuid_.String()

	var state proto.SecondAuthServerSaveState
	state.Type = resp.Type
	state.UserId = int(user.ID)
	stateBytes, _ := json.Marshal(state)
	worker.SetKVWithExpire(uuidStr, string(stateBytes), time.Minute*5) //二次认证允许时间

	resp.State = uuidStr
	resp.Expire = 5
	return &resp, nil
}

func UpdateUserCatalogue(user *dao.User, req *proto.UserCatalogueReq) (code int, msg string) {
	if user.Role != proto.USER_IS_ADMIN {
		code, msg = proto.PermissionDenied, "no permission"
		return code, msg
	}
	//查看目标目录是否有效
	userGroup := GetUserByIDWithCache(req.GroupID)
	if userGroup.Type == 0 {
		code, msg = proto.OperationFailed, "target group id is invalid"
	} else {
		//更新目标用户
		targetUser := GetUserByIDWithCache(req.UserId)
		targetUser.Prev = req.GroupID
		//更新用户
		dao.UpdateUserByIDV4(targetUser.ID, &targetUser)
		code, msg = proto.SuccessCode, "success"
	}
	return code, msg
}
