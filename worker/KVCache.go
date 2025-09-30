package worker

import (
	"log"
	"time"
	"user_center/proto"
)

func SetKV(key, value string){
	switch proto.Config.KV_TYPE {
	case proto.KV_TYPE_REDIS:
		SetRedis(key, value)
	case proto.KV_TYPE_BADGER:
		SetBadgerValue(key, value)
	default:
		log.Println("set don't surpport kv type")
	}
}

func SetKVWithExpire(key, value string, expire time.Duration) {
	switch proto.Config.KV_TYPE {
	case proto.KV_TYPE_REDIS:
		SetRedisWithExpire(key, value, expire)
	case proto.KV_TYPE_BADGER:
		SetBadgerValueWithExpire(key, value, expire)
	default:
		log.Println("set don't surpport kv type")
	}
}

func GetKV(key string) string {
	var res string
	switch proto.Config.KV_TYPE {
	case proto.KV_TYPE_REDIS:
		res = GetRedis(key)
	case proto.KV_TYPE_BADGER:
		res, _  = GetBadgerValue(key)
	default:
		log.Println("get don't surpport kv type")
	}
	return res	
}

func DelKV(key string) bool {
	res := true
	switch proto.Config.KV_TYPE {
	case proto.KV_TYPE_REDIS:
		DelRedis(key)
	case proto.KV_TYPE_BADGER:
		err := DelBadgerKey(key)
		if err != nil {
			res = false
		}
	default:
		log.Println("set don't surpport kv type")
		res = false
	}
	return res	
}


