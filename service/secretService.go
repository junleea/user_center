package service

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"log"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker"
)

func SyncSystemConfig(req *proto.SyncSystemConfigReq) (error, *proto.GenerateResp) {
	var resp proto.GenerateResp
	var respData proto.SyncSystemConfigResponse
	//查看是否有权限
	if req.SecretKeyMd5 == "" {
		log.Println("SyncSystemConfig Error: SecretKey is empty")
		resp.Code = proto.OperationFailed
		resp.Message = "Secret key md5 is null"
		return errors.New("secret key md5 is null"), &resp
	}
	//获取当前的secret
	secret, err := dao.GetSecretByMd5(req.SecretKeyMd5)
	if err != nil || secret.ID == 0 {
		log.Println("SyncSystemConfig Error getting secret by md5, err:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "Secret key md5 not found"
		return errors.New("get secret by md5 error"), &resp
	}
	//获取密钥信息
	redisKey := "secret_sync_settings"
	settingsStr := worker.GetRedis(redisKey)
	var secret_sync_settings proto.SecretSyncSettings
	err = json.Unmarshal([]byte(settingsStr), &secret_sync_settings)
	if err != nil {
		log.Println("SyncSystemConfig Error unmarshalling secret sync settings, err:", err)
		resp.Code = proto.OperationFailed
		resp.Message = "Error unmarshalling secret sync settings"
		return err, &resp
	}
	//对称加密
	next_secret_key_ase, err2 := worker.AESEncrypt([]byte(secret_sync_settings.Next), []byte(secret.SecretKey))
	if err2 != nil {
		log.Println("SyncSystemConfig Error encrypting secret key, err:", err2)
		resp.Code = proto.OperationFailed
		resp.Message = "Error encrypting secret key"
		return err2, &resp
	}
	respData.NewSecret, respData.NewTimestamp, respData.NewTimestamp = next_secret_key_ase, secret_sync_settings.NextStartTimestamp, time.Now().Unix()
	resp.Code = 0
	resp.Message = "Sync system config success"
	resp.Data = &respData
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

		hasher := md5.New()
		hasher.Write([]byte(secretKey))
		secret.SecretMd5 = string(hasher.Sum(nil))
		secret.SecretStart = time.Unix(startTime, 0)
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
	}
	settinsStr, err2 := json.Marshal(secret_sync_settings)
	if err2 != nil {
		log.Println("Error encoding set secret sync settings:", err2)
		return
	}
	worker.SetRedis(redisKey, string(settinsStr)) //将当前的密钥信息存入redis
}
