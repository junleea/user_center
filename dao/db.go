package dao

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"time"
	"user_center/proto"
)

var DB *gorm.DB

func Init() error {
	var db *gorm.DB
	var err error
	var dsn string
	logger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // 日志输出到标准输出
		logger.Config{
			SlowThreshold: time.Millisecond * time.Duration(proto.Config.SlowQueryThreshold), // 慢查询阈值设置
			//LogLevel:      logger.Info,                                                       // 日志级别设置为 Info，记录慢查询信息
			Colorful: true, // 启用日志颜色显示
		},
	)
	if proto.Config.DB == 0 {
		dsn = proto.Config.MYSQL_DSN
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
			Logger: logger,
		})
	} else if proto.Config.DB == 1 {
		dsn = proto.Config.PG_DSN
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
			Logger: logger,
		})
	}

	if err != nil {
		panic("failed to connect database")
		return err
	}
	err = db.AutoMigrate(&User{})
	if err != nil {
		fmt.Println("user table:", err)
		return err
	} // 自动迁移，创建表，如果表已经存在，会自动更新表结构，不会删除表,只会创建不存在的表

	DB = db
	return err
}

func Close() {
	sqlDB, err := DB.DB()
	if err != nil {
		panic("failed to connect database")
	}
	sqlDB.Close()
}

// 定义 MongoDB 客户端和集合
var mongoClient *mongo.Client

//var collection *mongo.Collection

func InitMongoDB() error {
	// 设置 MongoDB 客户端选项
	clientOptions := options.Client().ApplyURI(proto.Config.MONGO_URI)
	// 连接到 MongoDB
	var err error
	mongoClient, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Println("Error connecting to MongoDB:", err)
	} else {
		// 检查连接
		err = mongoClient.Ping(context.TODO(), nil)
		if err != nil {
			log.Println("Error pinging MongoDB:", err)
		} else {
			log.Println("Connected to MongoDB!")
		}
	}

	return err
}

func CloseMongoDB() {
	// 关闭 MongoDB 客户端
	if err := mongoClient.Disconnect(context.TODO()); err != nil {
		log.Println("Error disconnecting from MongoDB:", err)
	}
	log.Println("Disconnected from MongoDB!")
}
