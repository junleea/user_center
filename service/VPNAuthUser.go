package service

import (
	"sync"
	"user_center/proto"
)

type VPNAuthUserMap struct {
	UserMap map[uint]*[]proto.VPNAuthUserDPInfo
	mutex   sync.Mutex
}
