package service

import (
	"encoding/json"
	"errors"
	"log"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker"
)

func SyncSystemConfig(req *proto.SyncSystemConfigReq, requestID string) (error, *proto.GenerateResp) {
	var resp proto.GenerateResp
	var respData proto.SyncSystemConfigResponse
	//查看是否有权限
	if req.SecretKeyMd5 == "" {
		log.Println("requestID: ", requestID, "SyncSystemConfig Error: SecretKey is empty")
		resp.Code = proto.OperationFailed
		resp.Message = "Secret key md5 is null"
		return errors.New("secret key md5 is null"), &resp
	}
	//获取当前的secret
	secret, err := dao.GetSecretByMd5(req.SecretKeyMd5)
	if err != nil || secret.ID == 0 {
		log.Println("requestID: ", requestID, ",SyncSystemConfig Error getting secret by md5, err:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "Secret key md5 not found"
		return errors.New("get secret by md5 error"), &resp
	}
	//如果请求的密钥版本太老则不允许同步
	//获取当前的密钥信息
	currentSecret, err := dao.GetSecretKeyBySecret(proto.Config.TOKEN_SECRET)
	if err != nil || currentSecret.ID == 0 {
		log.Println("requestID: ", requestID, " SyncSystemConfig Error getting current secret, err:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "Current secret not found"
		return errors.New("get current secret error"), &resp
	}
	//比较版本
	if currentSecret.ID-secret.ID > 3 {
		log.Println("SyncSystemConfig Error: Secret version too old, current secret ID:", currentSecret.ID, "request secret ID:", secret.ID)
		resp.Code = proto.SigningKeyVersionIsTooOld
		resp.Message = "Secret version too old"
		return errors.New("secret version too old"), &resp
	}

	//获取密钥信息
	redisKey := "secret_sync_settings"
	settingsStr := worker.GetRedis(redisKey)
	var secret_sync_settings proto.SecretSyncSettings
	err = json.Unmarshal([]byte(settingsStr), &secret_sync_settings)
	if err != nil {
		log.Println("requestID: ", requestID, ", SyncSystemConfig Error unmarshalling secret sync settings, err:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "Error unmarshalling secret sync settings"
		return nil, &resp
	}
	////对称加密
	//next_secret_key_ase, err2 := worker.AESEncrypt([]byte(secret_sync_settings.Next), []byte(secret.SecretKey))
	//if err2 != nil {
	//	log.Println("SyncSystemConfig Error encrypting secret key, err:", err2)
	//	resp.Code = proto.OperationFailed
	//	resp.Message = "Error encrypting secret key"
	//	return err2, &resp
	//}
	respData.NewSecret, respData.NewTimestamp, respData.NewTimestamp = secret_sync_settings.Next, secret_sync_settings.NextStartTimestamp, time.Now().Unix()
	resp.Code = 0
	resp.Message = "Sync system config success"
	//将respData转为string,加密后返回
	respDataStr, err3 := json.Marshal(secret_sync_settings)
	if err3 != nil {
		log.Println("requestID: ", requestID, ",SyncSystemConfig Error marshalling response data, err:", err3)
		resp.Code = proto.OperationFailed
		resp.Message = "Error marshalling response data"
		return nil, &resp
	}
	//对称加密密钥。通过密钥加 secret_key 取md5
	secretKeyMd5 := worker.GenerateMD5(secret.SecretKey + "_sync_secret")
	//og.Println("SyncSystemConfig: Using secret key md5 for encryption:", secretKeyMd5)
	//对称加密
	next_secret_key_ase, err2 := worker.AESEncrypt(respDataStr, []byte(secretKeyMd5))
	if err2 != nil {
		log.Println("requestID: ", requestID, ",SyncSystemConfig Error encrypting response data, err:", err2)
		resp.Code = proto.OperationFailed
		resp.Message = "Error encrypting response data"
		return nil, &resp
	}
	resp.Data = next_secret_key_ase
	return nil, &resp
}

func SetSecretToDB(secretKey, prevSecretKey string, startTime int64) error {
	var err error
	//查看是否存在
	key, err2 := dao.GetSecretKeyBySecret(secretKey)
	if err2 != nil {
		log.Println("SetSecretToDB Error getting secret by key, err:", err2)
	}
	if key.ID == 0 {
		//不存在,创建
		var secret proto.Secret
		secret.SecretKey = secretKey
		//查看前一个secret
		if prevSecretKey == "" {
			secret.PrevSecretKeyID = 0
		} else {
			prevKey, _ := dao.GetSecretKeyBySecret(prevSecretKey)
			if prevKey.ID != 0 {
				secret.PrevSecretKeyID = prevKey.ID
			}
		}

		secret.SecretMd5 = worker.GenerateMD5(secretKey)
		secret.SecretStart = time.Unix(startTime, 0)
		log.Println("SetSecretToDB: Creating new secret with key:", secret.SecretKey, "and md5:", secret.SecretMd5)
		err4 := dao.CreateSecret(secret)
		if err4 != nil {
			return err4
		}
	} else {
		return err
	}
	return err
}

func SetNextSecretToCurrent(secret_copy proto.SecretSyncSettings) {
	var secret_sync_settings proto.SecretSyncSettings
	redisKey := "secret_sync_settings"
	settingsStr := worker.GetRedis(redisKey)
	err := json.Unmarshal([]byte(settingsStr), &secret_sync_settings)
	if err != nil {
		log.Println("Error decoding secret sync settings:", err)
	} else {
		//如果当前密钥的下一个密钥与传入的密钥不一致，则不进行设置
		if secret_copy.Next != secret_sync_settings.Next {
			return
		}
		//获取需要等待时间
		waitTime := secret_sync_settings.NextStartTimestamp - worker.GetCurrentTimestamp()
		if waitTime > 0 {
			log.Printf("Waiting for %d seconds before setting the next secret as current secret\n", waitTime)
			time.Sleep(time.Duration(waitTime) * time.Second) //等待时间
		} else {
			log.Println("No need to wait, setting the next secret as current secret immediately")
		}
		//设置下一个密钥为当前密钥
		secret_sync_settings.Prev = secret_sync_settings.Curr
		secret_sync_settings.PrevEndTimestamp = worker.GetCurrentTimestamp()
		secret_sync_settings.Curr = secret_sync_settings.Next
		secret_sync_settings.Next = ""
		secret_sync_settings.CurrStartTimestamp = secret_sync_settings.PrevEndTimestamp

		//设置当前程序的密钥
		//获取写锁
		proto.SigningKeyRWLock.Lock()
		defer proto.SigningKeyRWLock.Unlock()
		proto.SigningKey = []byte(secret_sync_settings.Curr)
		proto.Config.TOKEN_SECRET = secret_sync_settings.Curr
		go proto.WriteConfigToFileV2()
	}
	settinsStr, err2 := json.Marshal(secret_sync_settings)
	if err2 != nil {
		log.Println("Error encoding set secret sync settings:", err2)
		return
	}
	worker.SetRedis(redisKey, string(settinsStr)) //将当前的密钥信息存入redis
}
