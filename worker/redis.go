package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis/v8"
	"strconv"
	"time"
	"user_center/proto"
)

var RedisClient *redis.Client // Redis 客户端, 用于连接 Redis 服务器
func InitRedis() error {
	ctx := context.Background()

	if proto.Config.REDIS_User_PW == false {
		// 连接redis
		RedisClient = redis.NewClient(&redis.Options{
			Addr: proto.Config.REDIS_ADDR, // Redis 服务器地址
			DB:   proto.Config.REDIS_DB,   // 使用的数据库编号
		})
	} else {
		// 连接redis
		RedisClient = redis.NewClient(&redis.Options{
			Addr:     proto.Config.REDIS_ADDR,     // Redis 服务器地址
			Password: proto.Config.REDIS_PASSWORD, // 如果 Redis 设置了密码
			DB:       proto.Config.REDIS_DB,       // 使用的数据库编号
		})
	}

	// 验证 Redis 客户端是否可以正常工作
	_, err := RedisClient.Ping(ctx).Result()
	if err != nil {
		fmt.Println("Error connecting to Redis: %v", err)
	}
	return err
}

func CloseRedis() {
	// 关闭 Redis 客户端
	if err := RedisClient.Close(); err != nil {
		fmt.Println("Error closing Redis client: %v", err)
	}
}

func IsContainKey(key string) bool {
	ctx := context.Background()
	val, err := RedisClient.Exists(ctx, key).Result() // 检查键是否存在, 如果存在则返回 1, 否则返回 0
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return false
	}
	if val == 0 {
		return false
	}
	return true
}

// 设置redis
func SetRedis(key string, value string) bool {
	ctx := context.Background()
	// 设置键值对, 0 表示不设置过期时间, 如果需要设置过期时间, 可以设置为 time.Second * 10 等
	err := RedisClient.Set(ctx, key, value, time.Minute*30).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 设置redis,永久
func SetRedisForever(key string, value string) bool {
	ctx := context.Background()
	err := RedisClient.Set(ctx, key, value, 0).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 设置hash
func SetHashWithTime(key string, id int, name, email string, duration time.Duration) bool {
	//捕获错误，如果错误返回

	ctx := context.Background() // 创建一个上下文
	fields := map[string]interface{}{
		"id":    strconv.Itoa(id),
		"name":  name,
		"email": email,
	}

	// 设置哈希表的字段值, 0 表示不设置过期时间, 如果需要设置过期时间, 可以设置为 time.Second * 10 等
	err := RedisClient.HSet(ctx, key, fields).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	err = RedisClient.Expire(ctx, key, time.Hour*10).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 设置redis hash，设置过期时间
func SetHash(key string, data map[string]interface{}) bool {
	ctx := context.Background()
	err := RedisClient.HSet(ctx, key, data).Err()
	if err != nil {
		fmt.Println("%v :Error setting hash: %v", key, err)
		return false
	}
	err = RedisClient.Expire(ctx, key, time.Minute*30).Err()
	if err != nil {
		fmt.Println("%v :Error setting expire: %v", key, err)
		return false
	}
	return true
}

func SetHashWithField(key string, field string, value string) bool {
	ctx := context.Background()
	err := RedisClient.HSet(ctx, key, field, value).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

func GetHash(key string, field string) string {
	ctx := context.Background()
	val, err := RedisClient.HGet(ctx, key, field).Result()
	if err != nil {
		fmt.Println("Error getting hash: %v", err)
		return ""
	}
	return val
}

func GetHashAll(key string) map[string]string {
	ctx := context.Background()
	val, err := RedisClient.HGetAll(ctx, key).Result()
	if err != nil {
		fmt.Println("Error getting hash: %v", err)
		return nil
	}
	return val
}

// 设置redis
func SetRedisWithExpire(key string, value string, expire time.Duration) bool { // 设置键值对, 0 表示不设置过期时间, 如果需要设置过期时间, 可以设置为 time.Second * 10 等
	ctx := context.Background()
	// 设置键值对, 0 表示不设置过期时间, 如果需要设置过期时间, 可以设置为 time.Second * 10 等
	err := RedisClient.Set(ctx, key, value, expire).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 获取redis
func GetRedis(key string) string {
	ctx := context.Background()
	val, err := RedisClient.Get(ctx, key).Result() // 从 Redis 读取键值, 如果键不存在则返回空字符串, 如果出现错误则返回错误
	if err != nil {
		fmt.Println(key, " Error getting key: %v", err)
		return ""
	}
	return val
}

// pop redis list from right,as stack
func PopRedisList(key string) string {
	ctx := context.Background()
	val, err := RedisClient.RPop(ctx, key).Result() // 从 Redis 读取键值, 如果键不存在则返回空字符串, 如果出现错误则返回错误
	if err != nil {
		fmt.Println(key, " Error reading from Redis: %v", err)
		return ""
	}
	return val
}

// pop redis list from left,as queue
func PopRedisListLeft(key string) string {
	ctx := context.Background()
	val, err := RedisClient.LPop(ctx, key).Result() // 从 Redis 读取键值, 如果键不存在则返回空字符串, 如果出现错误则返回错误
	if err != nil {
		return ""
	}
	return val
}

func DelRedis(key string) {
	ctx := context.Background()
	err := RedisClient.Del(ctx, key).Err()
	if err != nil {
		fmt.Println("Error deleting key: %v", err)
	}
}

// push redis list from right
func PushRedisList(key string, value string) bool {
	ctx := context.Background()
	err := RedisClient.RPush(ctx, key, value).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

func GetRedisListLen(key string) int64 {
	ctx := context.Background()
	val, err := RedisClient.LLen(ctx, key).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return 0
	}
	return val
}

func PushRedisListWithExpire(key string, value string, expire time.Duration) bool {
	ctx := context.Background()
	err := RedisClient.RPush(ctx, key, value).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	err = RedisClient.Expire(ctx, key, expire).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// delete redis key
func delRedis(key string) {
	ctx := context.Background()
	err := RedisClient.Del(ctx, key).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
	}
}

// User 用户,用于存入 Redis hash
type RUser struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Age   int    `json:"age"`
	Email string `json:"email"`
}

func (u *RUser) toJSONString() string {
	// 将User对象编码为JSON字符串
	userJSON, err := json.Marshal(u)
	if err != nil {
		fmt.Println("Failed to marshal user: %v", err)
	}
	return string(userJSON)
}

// put hash to redis
func hSetRedis(key string, field string, value string) {
	ctx := context.Background()
	err := RedisClient.HSet(ctx, key, field, value).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
	}
}

// get hash from redis
func hGetRedis(key string, field string) string {
	ctx := context.Background()
	val, err := RedisClient.HGet(ctx, key, field).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
	}
	return val
}

// 设置set，有过期时间
func SetRedisSet(key string, values []string, expire time.Duration) bool {
	ctx := context.Background()
	err := RedisClient.SAdd(ctx, key, values).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	err = RedisClient.Expire(ctx, key, expire).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 设置set,添加元素
func SetRedisSetAdd(key string, value string) bool {
	ctx := context.Background()
	err := RedisClient.SAdd(ctx, key, value).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 批量添加元素
func SetRedisSetAddBatchWithExpire(key string, values []string, expire time.Duration) bool {
	ctx := context.Background()
	err := RedisClient.SAdd(ctx, key, values).Err()
	if err != nil {
		fmt.Println("SetRedisSetAddBatchWithExpire Error setting key: %v", err)
		return false
	}
	err = RedisClient.Expire(ctx, key, expire).Err()
	if err != nil {
		fmt.Println("SetRedisSetAddBatchWithExpire Error setting key: %v", err)
		return false
	}
	return true

}

// 设置set,添加元素
func SetRedisSetAddWithExpire(key string, value string, expire time.Duration) bool {
	ctx := context.Background()
	err := RedisClient.SAdd(ctx, key, value).Err()
	if err != nil {
		fmt.Println("SetRedisSetAddWithExpire Error setting key: %v", err)
		return false
	}
	err = RedisClient.Expire(ctx, key, expire).Err()
	if err != nil {
		fmt.Println("SetRedisSetAddWithExpire Error setting key: %v", err)
		return false
	}
	return true
}

// 设置set,删除元素
func SetRedisSetRemove(key string, value string) bool {
	ctx := context.Background()
	err := RedisClient.SRem(ctx, key, value).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 获取两个set的交集
func GetRedisSetIntersect(key1 string, key2 string) []string {
	ctx := context.Background()
	val, err := RedisClient.SInter(ctx, key1, key2).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return nil
	}
	return val
}

// 查看set是否包含元素
func IsContainSet(key string, value string) bool {
	ctx := context.Background()
	val, err := RedisClient.SIsMember(ctx, key, value).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return false
	}
	return val
}

// 查看set的所有元素
func GetRedisSetMembers(key string) []string {
	ctx := context.Background()
	val, err := RedisClient.SMembers(ctx, key).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return nil
	}
	return val
}

// BITMAP
func SetRedisBitmap(key string, offset int64, value int) bool {
	ctx := context.Background()
	err := RedisClient.SetBit(ctx, key, offset, value).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// BITMAP获取
func GetRedisBitmap(key string, offset int64) int {
	ctx := context.Background()
	val, err := RedisClient.GetBit(ctx, key, offset).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return 0
	}
	return int(val)
}

// 发布订阅者模式-发布消息
func Publish(channel string, message string, expire time.Duration) {
	ctx := context.Background()
	err := RedisClient.Publish(ctx, channel, message).Err()
	if err != nil {
		fmt.Println("Error publishing message: %v", err)
	}
	err = RedisClient.Expire(ctx, channel, expire).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
	}
}

// 发布订阅者模式-订阅消息
func Subscribe(channel string) []string {
	ctx := context.Background()
	pubsub := RedisClient.Subscribe(ctx, channel)
	ch := pubsub.Channel()
	defer pubsub.Close()
	var messages []string
	for msg := range ch {
		messages = append(messages, msg.Payload)
	}
	return messages
}

// redis两个set求差集存入第一个set
func SetRedisSetDiffAndStore(key1 string, key2 string) bool {
	ctx := context.Background()
	err := RedisClient.SDiffStore(ctx, key1, key1, key2).Err() //将key1和key2的差集存入key1
	if err != nil {
		fmt.Println("SetRedisSetDiffAndStore Error setting key: %v", err)
		return false
	}
	return true
}

// redis将第二个set存入第一个set
func SetRedisSetUnionAndStore(key1 string, key2 string) bool {
	ctx := context.Background()
	err := RedisClient.SUnionStore(ctx, key1, key1, key2).Err() //将key1和key2的并集存入key1
	if err != nil {
		fmt.Println("SetRedisSetUnionAndStore Error setting key: %v", err)
		return false
	}
	return true
}

// redis 清空set
func ClearRedisSet(key string) bool {
	ctx := context.Background()
	err := RedisClient.Del(ctx, key).Err()
	if err != nil {
		fmt.Println("Error setting key: %v", err)
		return false
	}
	return true
}

// 获取两个集合的并集
func GetRedisSetUnion(key1 string, key2 string) []string {
	ctx := context.Background()
	val, err := RedisClient.SUnion(ctx, key1, key2).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return nil
	}
	return val
}

type RedisInfo struct {
	Key    string
	Value  string
	Type   string
	Expire int // 过期时间, 单位: 秒
}

// 获取所有的key和value,及其对应的过期时间
func GetAllRedisInfo() ([]RedisInfo, error) {
	ctx := context.Background()
	keys, err := RedisClient.Keys(ctx, "*").Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return nil, err
	}
	var redisInfos []RedisInfo
	for _, key := range keys {
		//先查看key类型，再根据类型获取value
		key_type, val, err := getKeyTypeAndData(key)
		if err != nil {
			fmt.Println("Error getting key: %v", err)
			return nil, err
		}
		expire, err := RedisClient.TTL(ctx, key).Result()
		if err != nil {
			fmt.Println("Error getting key: %v", err)
			return nil, err
		}
		redisInfo := RedisInfo{
			Key:    key,
			Value:  val,
			Type:   key_type,
			Expire: int(expire.Seconds()),
		}
		redisInfos = append(redisInfos, redisInfo)
	}
	return redisInfos, nil
}

func getKeyTypeAndData(key string) (string, string, error) {
	ctx := context.Background()
	key_type := RedisClient.Type(ctx, key).Val()
	var val interface{}
	var err error
	switch key_type {
	case "string":
		val, err = RedisClient.Get(ctx, key).Result()
	case "hash":
		val, err = RedisClient.HGetAll(ctx, key).Result()
	case "list":
		val, err = RedisClient.LRange(ctx, key, 0, -1).Result()
	case "set":
		val, err = RedisClient.SMembers(ctx, key).Result()
	case "zset":
		val, err = RedisClient.ZRange(ctx, key, 0, -1).Result()
	case "bitmap":
		val, err = RedisClient.GetBit(ctx, key, 0).Result()
	default:
		val = "unknown type"
	}
	return key_type, fmt.Sprintf("%v", val), err
}

// 随机获取集合中的一个元素
func GetRedisSetRandomMember(key string) string {
	ctx := context.Background()
	val, err := RedisClient.SRandMember(ctx, key).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return ""
	}
	return val
}

func SetRedisSetIsMember(setKey, memberKey string) bool {
	ctx := context.Background()
	val, err := RedisClient.SIsMember(ctx, setKey, memberKey).Result()
	if err != nil {
		fmt.Println("Error getting key: %v", err)
		return false
	}
	return val
}
