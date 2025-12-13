package service

import (
	"log"
	"math"
	"net"
	"strconv"
	"sync"
	"user_center/proto"
)

type AddressPoolMap struct {
	PoolMap map[string]*IPAllocator
	mutex   sync.Mutex
}

var GlobalAddressPoolMap = AddressPoolMap{
	PoolMap: make(map[string]*IPAllocator),
}

type IPAllocator struct {
	ipv4Net    *net.IPNet
	ipv6Net    *net.IPNet
	ipv4Start  net.IP
	ipv4End    net.IP
	ipv6Start  net.IP
	ipv6End    net.IP
	ipv4Prefix int
	ipv6Prefix int
	ipv4Bitmap []byte
	ipv6Bitmap []byte
	mutex      sync.Mutex
}

func NewIPAllocator(ipv4Pool, ipv6Pool *proto.AddressPool) (ipa *IPAllocator, err error) {
	ipa = &IPAllocator{}
	ipa.mutex = sync.Mutex{}
	if ipv4Pool != nil {
		subStr := ipv4Pool.StartIP + "/" + strconv.Itoa(ipv4Pool.Prefix)
		_, ipv4Net, err2 := net.ParseCIDR(subStr)
		if err2 != nil {
			log.Println("[ERROR] NewIPAllocator:", err2)
			return nil, err
		}
		ipa.ipv4Net = ipv4Net
		ipa.ipv4Start = net.ParseIP(ipv4Pool.StartIP).To4()
		ipa.ipv4End = net.ParseIP(ipv4Pool.EndIP).To4()
		ipa.ipv4Prefix, _ = ipv4Net.Mask.Size()
		size := int(math.Pow(2, float64(32-ipa.ipv4Prefix)))
		bitmapSize := (size + 7) / 8
		ipa.ipv4Bitmap = make([]byte, bitmapSize)
	}
	if ipv6Pool != nil {
		//todo
	}
	return ipa, nil
}

func (ipa *IPAllocator) AllocateIP(userID uint, ipv4Pool, ipv6Pool *proto.AddressPool) (ipv4 net.IP, ipv6 net.IP, err error) {
	ipa.mutex.Lock()
	defer ipa.mutex.Unlock()
	//allocate ipv4
	//查看是否有绑定IP可用
	for _, bindIP := range ipv4Pool.IPBind {
		if uint(bindIP.UserID) == userID {
			ipv4_ := net.ParseIP(bindIP.BindIP).To4()
			//mark as used
			ipv4Offset := iv4pToOffsetBaseStartIP(ipv4_, ipa.ipv4Start)
			//该IP是否已经被使用
			if (ipa.ipv4Bitmap[ipv4Offset/8] & (1 << (ipv4Offset % 8))) != 0 {
				log.Println("[INFO]: user id:", userID, " Bound IPv4 address is already in use:", ipv4_)
			} else {
				ipa.ipv4Bitmap[ipv4Offset/8] |= 1 << (ipv4Offset % 8)
				log.Println("[INFO]: user id:", userID, " Allocated bound IPv4:", ipv4_)
				ipv4 = ipv4_
				return ipv4, nil, nil
			}
		}
	}
	//从bitmap中查找第一个未使用的IP
	for i := 0; i < len(ipa.ipv4Bitmap); i++ {
		if ipa.ipv4Bitmap[i] != 0xFF { // not all used
			for j := 0; j < 8; j++ {
				if (ipa.ipv4Bitmap[i] & (1 << j)) == 0 {
					//found free ip
					ipv4Offset := i*8 + j
					if ipv4Pool.IPBindMap[ipv4Offset] > 0 && uint(ipv4Pool.IPBindMap[ipv4Offset]) != userID {
						//该IP被绑定给其他用户，跳过
						continue
					}
					ipv4 = make(net.IP, 4)
					for k := 0; k < 4; k++ {
						ipv4[k] = ipa.ipv4Start[k] + byte((ipv4Offset>>(8*(3-k)))&0xFF)
					}
					//mark as used
					ipa.ipv4Bitmap[i] |= 1 << j
					log.Println("[INFO]: user id:", userID, "  Allocated IPv4:", ipv4)
					break
				}
			}
		}
		if ipv4 != nil {
			//如果分到的IP大于结束IP，则表示没有可用IP
			offset := iv4pToOffsetBaseStartIP(ipv4, ipa.ipv4Start)

			//计算结束IP的offset
			endOffset := iv4pToOffsetBaseStartIP(ipa.ipv4End, ipa.ipv4Start)
			if offset > endOffset {
				log.Println("[INFO]: user id:", userID, " No available IPv4 addresses within the specified range")
				ipv4 = nil
			}
			break

		}
	}
	if ipv4 == nil {
		log.Println("[INFO]: user id:", userID, " No available IPv4 addresses")
		return nil, nil, nil
	}

	return ipv4, ipv6, nil
}
func iv4pToOffsetBaseStartIP(ip, startIP net.IP) int {
	offset := 0
	for i := 0; i < 4; i++ {
		offset = offset<<8 + int(ip[i]-startIP[i])
	}
	return offset
}

func (ipa *IPAllocator) AddUseIP(ipv4, ipv6 net.IP) {
	ipv4Offset := iv4pToOffsetBaseStartIP(ipv4, ipa.ipv4Start)
	ipa.ipv4Bitmap[ipv4Offset/8] |= 1 << (ipv4Offset % 8)
}

func (ipa *IPAllocator) ReleaseIP(ipv4 net.IP, ipv6 net.IP) {
	ipv4Offset := iv4pToOffsetBaseStartIP(ipv4, ipa.ipv4Start)
	ipa.ipv4Bitmap[ipv4Offset/8] &^= 1 << (ipv4Offset % 8)
}
