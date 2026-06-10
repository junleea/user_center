package user_center_test

import (
	"log"
	"net"
	"testing"
	"time"
	"user_center/proto"
	"user_center/service"
)
func ip(s string) net.IP { return net.ParseIP(s) }

func TestAllocateIPPool(t *testing.T) {

	ip4_bind := []proto.UserIDBindIP{}
	ip4_bind = append(ip4_bind, proto.UserIDBindIP{UserID: 1, BindIP: "10.0.1.2"})
	ip4_bind = append(ip4_bind, proto.UserIDBindIP{UserID: 2, BindIP: "10.0.1.4"})
	ip4_bind = append(ip4_bind, proto.UserIDBindIP{UserID: 2, BindIP: "10.0.1.5"})
	ipv4 := proto.AddressPool{
		StartIP: "10.0.1.1",
		EndIP:   "10.0.1.255",
		Prefix:  24,
		IPBind: ip4_bind,
	}
	ip6_bind := []proto.UserIDBindIP{}
	ip6_bind = append(ip6_bind, proto.UserIDBindIP{UserID: 1, BindIP: "2001:db8:1::2"})
	ipv6 := proto.AddressPool{
		StartIP: "2001:db8:1::1",
		EndIP:   "2001:db8:1::ffff",
		Prefix:  112,
		IPBind: ip6_bind,
	}
	ipallocator, err := service.NewIPAllocator(&ipv4, &ipv6)
	if err != nil {
		t.Fatal(err)
	}

	for i := 2; i < 65; i++ { 
		//go func() {
			ip, ip6, err := ipallocator.AllocateIP(i)
			if err != nil {
				t.Fatal(err)
				return
			}
			log.Println("ipv4:", ip.String(), " ipv6:", ip6.String(), " user:", i)
		//}()
	}
	ip, ip6, err := ipallocator.AllocateIP(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("ipv4:", ip.String())
	t.Log("ipv6:", ip6.String())
	log.Println("ipv4:", ip.String(), " ipv6:", ip6.String())
	if ip.String() != "10.255.1.2" {
		t.Fatal("ipv4:", ip.String(), " ipv6:", ip6.String())
	}
	if ip6.String() != "2001:db8:1::2" {
		t.Fatal("ipv4:", ip.String(), " ipv6:", ip6.String())
	}
	time.Sleep(time.Second * 100)
}