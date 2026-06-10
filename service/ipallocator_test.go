package service

import (
	"net"
	"testing"

	"user_center/proto"
)

// ---------------------------------------------------------------------------
// IPPool (IPv4) tests
// ---------------------------------------------------------------------------

func TestIPPool_New_InvalidStartIP(t *testing.T) {
	_, err := New(net.ParseIP(""), net.ParseIP("10.0.0.10"), 24, nil)
	if err == nil {
		t.Fatal("expected error for invalid start IP")
	}
}

func TestIPPool_New_StartGreaterThanEnd(t *testing.T) {
	_, err := New(net.ParseIP("10.0.0.10"), net.ParseIP("10.0.0.1"), 24, nil)
	if err == nil {
		t.Fatal("expected error for start > end")
	}
}

func TestIPPool_New_BindingOutOfRange(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.1.1")}, // outside [10.0.0.1, 10.0.0.10]
	}
	_, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err == nil {
		t.Fatal("expected error for binding out of range")
	}
}

func TestIPPool_New_BindingInvalidIP(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {nil}, // nil IP
	}
	_, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err == nil {
		t.Fatal("expected error for invalid IP in bindings")
	}
}

func TestIPPool_New_Success(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.count != 10 {
		t.Fatalf("expected count=10, got %d", p.count)
	}
}

func TestIPPool_New_WithBindings(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3")},
		2: {net.ParseIP("10.0.0.3")}, // shared reservation
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()
	if stats.Reserved != 2 { // 10.0.0.2 and 10.0.0.3 are reserved (shared counts once)
		t.Fatalf("expected 2 reserved, got %d", stats.Reserved)
	}
	if stats.Free != 8 {
		t.Fatalf("expected 8 free, got %d", stats.Free)
	}
}

func TestIPPool_Allocate_ReservedIP(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.5")},
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.Allocate(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip)
	}
}

func TestIPPool_Allocate_GeneralPool(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.Allocate(100)
	if err != nil {
		t.Fatal(err)
	}
	// Should get the first free (unallocated, unreserved) IP
	if !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}
}

func TestIPPool_Allocate_PoolExhausted(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Allocate(1)
	p.Allocate(2)
	_, err = p.Allocate(3)
	if err == nil {
		t.Fatal("expected pool exhausted error")
	}
}

func TestIPPool_AllocateByIP_Success(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip)
	}
}

func TestIPPool_AllocateByIP_AlreadyAllocated(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	_, err = p.AllocateByIP(2, net.ParseIP("10.0.0.5"))
	if err == nil {
		t.Fatal("expected already allocated error")
	}
}

func TestIPPool_AllocateByIP_OutOfRange(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.AllocateByIP(1, net.ParseIP("10.0.1.1"))
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestIPPool_AllocateByIP_ReservedForOtherUser(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.5")},
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.AllocateByIP(2, net.ParseIP("10.0.0.5"))
	if err == nil {
		t.Fatal("expected reserved for other users error")
	}
}

func TestIPPool_AllocateByIP_ReservedForSameUser(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.5")},
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip)
	}
}

func TestIPPool_Release(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if !p.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected IP to be allocated")
	}
	err = p.Release(net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if p.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected IP to be released")
	}
}

func TestIPPool_Release_OutOfRange(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.Release(net.ParseIP("10.0.1.1"))
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestIPPool_Release_InvalidIP(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.Release(nil)
	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func TestIPPool_Release_Idempotent(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Release an IP that was never allocated — should be no-op
	err = p.Release(net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestIPPool_AddBinding(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.AddBinding(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	// User 1 should now be able to allocate their reserved IP
	ip, err := p.Allocate(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip)
	}
}

func TestIPPool_AddBinding_OutOfRange(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.AddBinding(1, net.ParseIP("10.0.1.1"))
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestIPPool_RemoveBinding(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.5")},
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	// After removal, the IP should be available in the general pool
	ip, err := p.Allocate(2)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected first general pool IP 10.0.0.1, got %s", ip)
	}
}

func TestIPPool_RemoveBinding_NotBound(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("10.0.0.5"))
	if err == nil {
		t.Fatal("expected no bindings error")
	}
}

func TestIPPool_RemoveBinding_WrongIP(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.5")},
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("10.0.0.6"))
	if err == nil {
		t.Fatal("expected IP not bound error")
	}
}

func TestIPPool_RemoveBinding_SharedReservation(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.5")},
		2: {net.ParseIP("10.0.0.5")}, // shared
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	// Remove user 1's binding — user 2 still reserves it
	err = p.RemoveBinding(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	// User 2 should still be able to allocate it
	ip, err := p.Allocate(2)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip)
	}
	// User 1 should not get it (no longer reserved for them)
	_, err = p.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if err == nil {
		t.Fatal("expected reserved for other users error")
	}
}

func TestIPPool_IsAllocated_OutOfRange(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.IsAllocated(net.ParseIP("10.0.1.1")) {
		t.Fatal("expected false for out-of-range IP")
	}
}

func TestIPPool_Stats(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Allocate(1)
	p.Allocate(2)
	stats := p.Stats()
	if stats.Total != 10 {
		t.Fatalf("expected total=10, got %d", stats.Total)
	}
	if stats.Allocated != 2 {
		t.Fatalf("expected allocated=2, got %d", stats.Allocated)
	}
	if stats.Free != 8 {
		t.Fatalf("expected free=8, got %d", stats.Free)
	}
}

func TestIPPool_Stats_String(t *testing.T) {
	s := Stats{Total: 10, Allocated: 2, Reserved: 3, Free: 5}
	expected := "total=10 allocated=2 reserved=3 free=5"
	if s.String() != expected {
		t.Fatalf("expected %q, got %q", expected, s.String())
	}
}

func TestIPPool_Allocate_SequentialAllocation(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.5"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ip, err := p.Allocate(i + 1)
		if err != nil {
			t.Fatal(err)
		}
		expected := net.ParseIP("10.0.0.1")
		expected = expected.To4()
		expected[3] = byte(i + 1)
		if !ip.Equal(expected) {
			t.Fatalf("allocation %d: expected %s, got %s", i+1, expected, ip)
		}
	}
}

func TestIPPool_Allocate_ReuseAfterRelease(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AllocateByIP(1, net.ParseIP("10.0.0.1"))
	p.AllocateByIP(2, net.ParseIP("10.0.0.2"))
	p.AllocateByIP(3, net.ParseIP("10.0.0.3"))

	p.Release(net.ParseIP("10.0.0.2"))

	ip, err := p.Allocate(4)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected reused 10.0.0.2, got %s", ip)
	}
}

func TestIPPool_AllocateByIP_InvalidIP(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.AllocateByIP(1, net.ParseIP("invalid"))
	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

// ---------------------------------------------------------------------------
// IPPool6 (IPv6) tests
// ---------------------------------------------------------------------------

func TestIPPool6_New_PrefixTooLow(t *testing.T) {
	_, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 64, nil)
	if err == nil {
		t.Fatal("expected error for prefix < 112")
	}
}

func TestIPPool6_New_PrefixTooHigh(t *testing.T) {
	_, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 129, nil)
	if err == nil {
		t.Fatal("expected error for prefix > 128")
	}
}

func TestIPPool6_New_StartGreaterThanEnd(t *testing.T) {
	_, err := New6(net.ParseIP("2001:db8::ffff"), net.ParseIP("2001:db8::1"), 112, nil)
	if err == nil {
		t.Fatal("expected error for start > end")
	}
}

func TestIPPool6_New_BindingOutOfRange(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("2001:db8:1::1")}, // outside [2001:db8::1, 2001:db8::ffff]
	}
	_, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err == nil {
		t.Fatal("expected error for binding out of range")
	}
}

func TestIPPool6_New_InvalidBindingIP(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {nil},
	}
	_, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err == nil {
		t.Fatal("expected error for invalid IP in bindings")
	}
}

func TestIPPool6_New_Success(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()
	if stats.Total != 65535 {
		t.Fatalf("expected total=65535, got %d", stats.Total)
	}
}

func TestIPPool6_New_WithBindings(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("2001:db8::2")},
		2: {net.ParseIP("2001:db8::3")},
	}
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()
	if stats.Reserved != 2 {
		t.Fatalf("expected 2 reserved, got %d", stats.Reserved)
	}
}

func TestIPPool6_Allocate_ReservedIP(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("2001:db8::5")},
	}
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.Allocate(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("expected 2001:db8::5, got %s", ip)
	}
}

func TestIPPool6_Allocate_GeneralPool(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.Allocate(100)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected 2001:db8::1, got %s", ip)
	}
}

func TestIPPool6_Allocate_PoolExhausted(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::3"), 126, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Allocate(1)
	p.Allocate(2)
	p.Allocate(3)
	_, err = p.Allocate(4)
	if err == nil {
		t.Fatal("expected pool exhausted error")
	}
}

func TestIPPool6_AllocateByIP_Success(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.AllocateByIP(1, net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("expected 2001:db8::5, got %s", ip)
	}
}

func TestIPPool6_AllocateByIP_AlreadyAllocated(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AllocateByIP(1, net.ParseIP("2001:db8::5"))
	_, err = p.AllocateByIP(2, net.ParseIP("2001:db8::5"))
	if err == nil {
		t.Fatal("expected already allocated error")
	}
}

func TestIPPool6_AllocateByIP_OutOfRange(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.AllocateByIP(1, net.ParseIP("2001:db8:1::1"))
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestIPPool6_AllocateByIP_ReservedForOtherUser(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("2001:db8::5")},
	}
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.AllocateByIP(2, net.ParseIP("2001:db8::5"))
	if err == nil {
		t.Fatal("expected reserved for other users error")
	}
}

func TestIPPool6_Release(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AllocateByIP(1, net.ParseIP("2001:db8::5"))
	if !p.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected IP to be allocated")
	}
	err = p.Release(net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
	if p.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected IP to be released")
	}
}

func TestIPPool6_Release_OutOfRange(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.Release(net.ParseIP("2001:db8:1::1"))
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestIPPool6_AddBinding(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.AddBinding(1, net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
	ip, err := p.Allocate(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("expected 2001:db8::5, got %s", ip)
	}
}

func TestIPPool6_AddBinding_OutOfRange(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.AddBinding(1, net.ParseIP("2001:db8:1::1"))
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestIPPool6_RemoveBinding(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("2001:db8::5")},
	}
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestIPPool6_RemoveBinding_NotBound(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("2001:db8::5"))
	if err == nil {
		t.Fatal("expected no bindings error")
	}
}

func TestIPPool6_RemoveBinding_SharedReservation(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("2001:db8::5")},
		2: {net.ParseIP("2001:db8::5")},
	}
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
	// User 2 should still get it as reserved
	ip, err := p.Allocate(2)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("expected 2001:db8::5, got %s", ip)
	}
}

func TestIPPool6_IsAllocated_OutOfRange(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.IsAllocated(net.ParseIP("2001:db8:1::1")) {
		t.Fatal("expected false for out-of-range IP")
	}
}

func TestIPPool6_Stats(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::10"), 124, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Allocate(1)
	stats := p.Stats()
	if stats.Allocated != 1 {
		t.Fatalf("expected allocated=1, got %d", stats.Allocated)
	}
}

func TestIPPool6_Stats6_String(t *testing.T) {
	s := Stats6{Total: 10, Allocated: 2, Reserved: 3, Free: 5}
	expected := "total=10 allocated=2 reserved=3 free=5"
	if s.String() != expected {
		t.Fatalf("expected %q, got %q", expected, s.String())
	}
}

func TestIPPool6_Release_ReuseAfterRelease(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::3"), 126, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AllocateByIP(1, net.ParseIP("2001:db8::1"))
	p.AllocateByIP(2, net.ParseIP("2001:db8::2"))
	p.AllocateByIP(3, net.ParseIP("2001:db8::3"))

	p.Release(net.ParseIP("2001:db8::2"))

	ip, err := p.Allocate(4)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("expected reused 2001:db8::2, got %s", ip)
	}
}

// ---------------------------------------------------------------------------
// IPAllocator tests
// ---------------------------------------------------------------------------

func newTestAllocator(t *testing.T) *IPAllocator {
	t.Helper()
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
	}
	a, err := NewIPAllocator(ipv4, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestIPAllocator_NewIPAllocator_DualStack(t *testing.T) {
	a := newTestAllocator(t)
	if a.v4 == nil || a.v6 == nil {
		t.Fatal("expected both v4 and v6 pools")
	}
}

func TestIPAllocator_NewIPAllocator_IPv4Only(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	a, err := NewIPAllocator(ipv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.v4 == nil {
		t.Fatal("expected v4 pool")
	}
	if a.v6 != nil {
		t.Fatal("expected no v6 pool")
	}
}

func TestIPAllocator_NewIPAllocator_IPv6Only(t *testing.T) {
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
	}
	a, err := NewIPAllocator(nil, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	if a.v6 == nil {
		t.Fatal("expected v6 pool")
	}
	if a.v4 != nil {
		t.Fatal("expected no v4 pool")
	}
}

func TestIPAllocator_NewIPAllocator_NoPools(t *testing.T) {
	_, err := NewIPAllocator(nil, nil)
	if err == nil {
		t.Fatal("expected error when no pools configured")
	}
}

func TestIPAllocator_NewIPAllocator_EmptyStartIP(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	a, err := NewIPAllocator(ipv4, nil)
	if err != nil {
		t.Fatal("empty StartIP should be treated as not configured, not error")
	}
	if a.v4 != nil {
		t.Fatal("expected no v4 pool when StartIP is empty")
	}
}

func TestIPAllocator_NewIPAllocator_InvalidIPs(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "invalid",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	_, err := NewIPAllocator(ipv4, nil)
	if err == nil {
		t.Fatal("expected error for invalid IPs")
	}
}

func TestIPAllocator_NewIPAllocator_WithBindings(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
		IPBind: []proto.UserIDBindIP{
			{UserID: 1, BindIP: "10.0.0.5"},
		},
	}
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
		IPBind: []proto.UserIDBindIP{
			{UserID: 1, BindIP: "2001:db8::5"},
		},
	}
	a, err := NewIPAllocator(ipv4, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	ip4, ip6, err := a.AllocateIP(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip4.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip4)
	}
	if !ip6.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("expected 2001:db8::5, got %s", ip6)
	}
}

func TestIPAllocator_AllocateIP(t *testing.T) {
	a := newTestAllocator(t)
	ip4, ip6, err := a.AllocateIP(1)
	if err != nil {
		t.Fatal(err)
	}
	if ip4 == nil {
		t.Fatal("expected IPv4 address")
	}
	if ip6 == nil {
		t.Fatal("expected IPv6 address")
	}
}

func TestIPAllocator_AllocateIP_IPv4Only(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	a, err := NewIPAllocator(ipv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	ip4, ip6, err := a.AllocateIP(1)
	if err != nil {
		t.Fatal(err)
	}
	if ip4 == nil {
		t.Fatal("expected IPv4 address")
	}
	if ip6 != nil {
		t.Fatal("expected no IPv6 address")
	}
}

func TestIPAllocator_AllocateIP_PoolExhausted(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.1",
		Prefix:  24,
	}
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::1",
		Prefix:  128,
	}
	a, err := NewIPAllocator(ipv4, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	a.AllocateIP(1)
	_, _, err = a.AllocateIP(2)
	if err == nil {
		t.Fatal("expected pool exhausted error")
	}
}

func TestIPAllocator_AllocateByIP_IPv4(t *testing.T) {
	a := newTestAllocator(t)
	ip, err := a.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip)
	}
}

func TestIPAllocator_AllocateByIP_IPv6(t *testing.T) {
	a := newTestAllocator(t)
	ip, err := a.AllocateByIP(1, net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("expected 2001:db8::5, got %s", ip)
	}
}

func TestIPAllocator_AllocateByIP_NoV4Pool(t *testing.T) {
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
	}
	a, err := NewIPAllocator(nil, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if err == nil {
		t.Fatal("expected no IPv4 pool error")
	}
}

func TestIPAllocator_AllocateByIP_NoV6Pool(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	a, err := NewIPAllocator(ipv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.AllocateByIP(1, net.ParseIP("2001:db8::5"))
	if err == nil {
		t.Fatal("expected no IPv6 pool error")
	}
}

func TestIPAllocator_ReleaseIP_IPv4(t *testing.T) {
	a := newTestAllocator(t)
	a.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if !a.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected allocated")
	}
	err := a.ReleaseIP(net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if a.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected released")
	}
}

func TestIPAllocator_ReleaseIP_IPv6(t *testing.T) {
	a := newTestAllocator(t)
	a.AllocateByIP(1, net.ParseIP("2001:db8::5"))
	if !a.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected allocated")
	}
	err := a.ReleaseIP(net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
	if a.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected released")
	}
}

func TestIPAllocator_ReleaseIP_NoV4Pool(t *testing.T) {
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
	}
	a, err := NewIPAllocator(nil, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	err = a.ReleaseIP(net.ParseIP("10.0.0.5"))
	if err == nil {
		t.Fatal("expected no IPv4 pool error")
	}
}

func TestIPAllocator_ReleaseIP_NoV6Pool(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	a, err := NewIPAllocator(ipv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = a.ReleaseIP(net.ParseIP("2001:db8::5"))
	if err == nil {
		t.Fatal("expected no IPv6 pool error")
	}
}

func TestIPAllocator_AddUseIP(t *testing.T) {
	a := newTestAllocator(t)
	a.AddUseIP(net.ParseIP("10.0.0.5"))
	if !a.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected 10.0.0.5 to be allocated")
	}
	// Adding again should be silently ignored
	a.AddUseIP(net.ParseIP("10.0.0.5"))
}

func TestIPAllocator_AddUseIP_IPv6(t *testing.T) {
	a := newTestAllocator(t)
	a.AddUseIP(net.ParseIP("2001:db8::5"))
	if !a.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected 2001:db8::5 to be allocated")
	}
}

func TestIPAllocator_AddUseIP_Nil(t *testing.T) {
	a := newTestAllocator(t)
	a.AddUseIP(nil) // should not panic
}

func TestIPAllocator_AddUseIP_OutOfRange(t *testing.T) {
	a := newTestAllocator(t)
	a.AddUseIP(net.ParseIP("10.0.1.1")) // silently ignored
}

func TestIPAllocator_AddUseIPByStr(t *testing.T) {
	a := newTestAllocator(t)
	a.AddUseIPByStr("10.0.0.5", "2001:db8::5")
	if !a.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected 10.0.0.5 to be allocated")
	}
	if !a.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected 2001:db8::5 to be allocated")
	}
}

func TestIPAllocator_AddUseIPByStr_Empty(t *testing.T) {
	a := newTestAllocator(t)
	a.AddUseIPByStr("", "") // should not panic
}

func TestIPAllocator_IsAllocated_IPv4(t *testing.T) {
	a := newTestAllocator(t)
	if a.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected not allocated")
	}
	a.AllocateByIP(1, net.ParseIP("10.0.0.5"))
	if !a.IsAllocated(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected allocated")
	}
}

func TestIPAllocator_IsAllocated_IPv6(t *testing.T) {
	a := newTestAllocator(t)
	if a.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected not allocated")
	}
	a.AllocateByIP(1, net.ParseIP("2001:db8::5"))
	if !a.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected allocated")
	}
}

func TestIPAllocator_Stats(t *testing.T) {
	a := newTestAllocator(t)
	v4, v6 := a.Stats()
	if v4.Total != 10 {
		t.Fatalf("expected v4 total=10, got %d", v4.Total)
	}
	if v6.Total != 65535 {
		t.Fatalf("expected v6 total=65535, got %d", v6.Total)
	}
}

func TestIPAllocator_BindIP_IPv4(t *testing.T) {
	a := newTestAllocator(t)
	err := a.BindIP(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	ip4, _, err := a.AllocateIP(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip4.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s", ip4)
	}
}

func TestIPAllocator_BindIP_IPv6(t *testing.T) {
	a := newTestAllocator(t)
	err := a.BindIP(1, net.ParseIP("2001:db8::5"))
	if err != nil {
		t.Fatal(err)
	}
	_, ip6, err := a.AllocateIP(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip6.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("expected 2001:db8::5, got %s", ip6)
	}
}

func TestIPAllocator_BindIP_NoV4Pool(t *testing.T) {
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
	}
	a, err := NewIPAllocator(nil, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	err = a.BindIP(1, net.ParseIP("10.0.0.5"))
	if err == nil {
		t.Fatal("expected no IPv4 pool error")
	}
}

func TestIPAllocator_UnbindIP_IPv4(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
		IPBind: []proto.UserIDBindIP{
			{UserID: 1, BindIP: "10.0.0.5"},
		},
	}
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
	}
	a, err := NewIPAllocator(ipv4, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	err = a.UnbindIP(1, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestIPAllocator_UnbindIP_NoV6Pool(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	a, err := NewIPAllocator(ipv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = a.UnbindIP(1, net.ParseIP("2001:db8::5"))
	if err == nil {
		t.Fatal("expected no IPv6 pool error")
	}
}

func TestIPAllocator_NewIPAllocator_InvalidBindingIP(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
		IPBind: []proto.UserIDBindIP{
			{UserID: 1, BindIP: "not-an-ip"},
		},
	}
	ipv6 := &proto.AddressPool{
		StartIP: "2001:db8::1",
		EndIP:   "2001:db8::ffff",
		Prefix:  112,
	}
	// Invalid BindIP should be silently skipped
	a, err := NewIPAllocator(ipv4, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("expected allocator to be created (invalid binding skipped)")
	}
}

func TestIPPool6_AllocateByIP_InvalidIP(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Pass an IPv4 address to the IPv6 pool
	_, err = p.AllocateByIP(1, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected invalid IPv6 address error")
	}
}

func TestIPPool6_Release_InvalidIP(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.Release(net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected invalid IPv6 address error")
	}
}

func TestIPPool6_AddBinding_InvalidIP(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.AddBinding(1, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected invalid IPv6 address error")
	}
}

func TestIPPool6_RemoveBinding_InvalidIP(t *testing.T) {
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected invalid IPv6 address error")
	}
}

func TestIPPool6_RemoveBinding_WrongIP(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("2001:db8::5")},
	}
	p, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 112, bindings)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("2001:db8::6"))
	if err == nil {
		t.Fatal("expected IP not bound error")
	}
}

// ---------------------------------------------------------------------------
// uint128 / helpers
// ---------------------------------------------------------------------------

func TestUint128_Conversion(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	u, ok := ipToUint128(ip)
	if !ok {
		t.Fatal("expected successful conversion")
	}
	roundTrip := u.toIP()
	if !roundTrip.Equal(ip) {
		t.Fatalf("round-trip failed: %s != %s", roundTrip, ip)
	}
}

func TestUint128_Cmp(t *testing.T) {
	a := uint128{hi: 0, lo: 1}
	b := uint128{hi: 0, lo: 2}
	if cmp128(a, b) >= 0 {
		t.Fatal("expected a < b")
	}
	if cmp128(b, a) <= 0 {
		t.Fatal("expected b > a")
	}
	if cmp128(a, a) != 0 {
		t.Fatal("expected a == a")
	}
	c := uint128{hi: 1, lo: 0}
	if cmp128(a, c) >= 0 {
		t.Fatal("expected a < c (hi differs)")
	}
}

func TestUint128_Sub128(t *testing.T) {
	a := uint128{hi: 0, lo: 10}
	b := uint128{hi: 0, lo: 3}
	diff, ok := sub128(a, b)
	if !ok || diff != 7 {
		t.Fatalf("expected 7, got %d", diff)
	}
	// a < b
	_, ok = sub128(b, a)
	if ok {
		t.Fatal("expected false when a < b")
	}
}

func TestUint128_Sub128_Borrow(t *testing.T) {
	a := uint128{hi: 1, lo: 0}
	b := uint128{hi: 0, lo: 1}
	diff, ok := sub128(a, b)
	if !ok {
		t.Fatal("expected success with borrow")
	}
	if diff != 0xFFFFFFFFFFFFFFFF {
		t.Fatalf("expected max uint64, got %d", diff)
	}
}

func TestUint128_Sub128_HiDiffTooLarge(t *testing.T) {
	a := uint128{hi: 3, lo: 0}
	b := uint128{hi: 1, lo: 0}
	_, ok := sub128(a, b)
	if ok {
		t.Fatal("expected false when hi diff > 1")
	}
}

func TestIPPool6_New_RangeExceedsPrefix(t *testing.T) {
	// /120 allows 256 IPs; requesting 65535 should fail
	_, err := New6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::ffff"), 120, nil)
	if err == nil {
		t.Fatal("expected range exceeds prefix error")
	}
}

func TestIPPool_AllocateByIP_InvalidIPv6(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.AllocateByIP(1, net.ParseIP("2001:db8::1"))
	if err == nil {
		t.Fatal("expected invalid IPv4 address error")
	}
}

func TestIPPool_AddBinding_InvalidIP(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.AddBinding(1, net.ParseIP("2001:db8::1"))
	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func TestIPPool_RemoveBinding_InvalidIP(t *testing.T) {
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = p.RemoveBinding(1, net.ParseIP("2001:db8::1"))
	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func TestIPAllocator_IsAllocated_NoPool(t *testing.T) {
	ipv4 := &proto.AddressPool{
		StartIP: "10.0.0.1",
		EndIP:   "10.0.0.10",
		Prefix:  24,
	}
	a, err := NewIPAllocator(ipv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Check IPv6 on IPv4-only allocator
	if a.IsAllocated(net.ParseIP("2001:db8::5")) {
		t.Fatal("expected false when no IPv6 pool")
	}
}

func TestIPPool_Allocate_MultipleReservedThenGeneral(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.3")},
		2: {net.ParseIP("10.0.0.5")},
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	// User 1 gets their reserved IP
	ip1, err := p.Allocate(1)
	if err != nil || !ip1.Equal(net.ParseIP("10.0.0.3")) {
		t.Fatalf("expected 10.0.0.3, got %s, err=%v", ip1, err)
	}
	// User 2 gets their reserved IP
	ip2, err := p.Allocate(2)
	if err != nil || !ip2.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected 10.0.0.5, got %s, err=%v", ip2, err)
	}
	// User 3 gets a general pool IP
	ip3, err := p.Allocate(3)
	if err != nil || !ip3.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected 10.0.0.1, got %s, err=%v", ip3, err)
	}
}

func TestIPPool_Allocate_ReservedAllUsed(t *testing.T) {
	bindings := map[int][]net.IP{
		1: {net.ParseIP("10.0.0.2")},
	}
	p, err := New(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10"), 24, bindings)
	if err != nil {
		t.Fatal(err)
	}
	// First allocation: reserved IP
	ip1, err := p.Allocate(1)
	if err != nil || !ip1.Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected 10.0.0.2, got %s", ip1)
	}
	// Second allocation for same user: should fall to general pool
	ip2, err := p.Allocate(1)
	if err != nil {
		t.Fatal(err)
	}
	if !ip2.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected 10.0.0.1 from general pool, got %s", ip2)
	}
}
