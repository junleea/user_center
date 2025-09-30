package worker

import (
	"log"
	"time"
	"user_center/proto"
	"github.com/dgraph-io/badger/v4"
)
var badger_db *badger.DB

func InitBadger(){
	// 配置数据库选项
	opts := badger.DefaultOptions(proto.Config.BADGER_DATA_PATH) // 数据存储目录
	// 可选配置：调整内存限制（默认 1GB）
	//opts.MemoryMapSize = 2 << 27

	// 打开数据库
	db, err := badger.Open(opts)
	if err != nil {
		panic("can't open badger")
	}else{
		log.Println("badger has opened!")
	}
	badger_db = db
}

func CloseBadger() {
	badger_db.Close()
}

func SetBadgerValue(key_ string, value_ string){
	err := badger_db.Update(func(txn *badger.Txn) error {
		key := []byte(key_)
		value := []byte(value_)
		return txn.Set(key, value)
	})
	if err != nil {
		log.Println("set badger db key:%s, err: %w", key_, err)
	}
}

func SetBadgerValueWithExpire(key_ string, value_ string, expire time.Duration ){
	err := badger_db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key_), []byte(value_)).WithTTL(expire)
		return txn.SetEntry(e)
	})
	if err != nil {
		log.Println("set badger db key: %s, err: %w", key_, err)
	}
}

func GetBadgerValue(key string) (string, error) {

	var value []byte
	err := badger_db.View(func(tx *badger.Txn) error {
		item, err := tx.Get([]byte(key))
		if err != nil {
			return err
		}

		// 复制值到新的字节切片
		valCopy, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		value = valCopy
		return nil
	})
	return string(value), err
}

func DelBadgerKey(key string) error {
	return badger_db.Update(func(tx *badger.Txn) error {
		return tx.Delete([]byte(key))
	})
}
