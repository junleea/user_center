package service

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/bits"
	"net"
	"sync"
	"math"
	"user_center/dao"
	"user_center/proto"
)

type AddressPoolMap struct {
	PoolMap map[string]*IPAllocator
	mutex   sync.Mutex
}

var GlobalAddressPoolAllocatorMap = AddressPoolMap{
	PoolMap: make(map[string]*IPAllocator),
}


func InitAddressPoolToMap() (err error) {
	//获取地址池信息
	poolConf := dao.GetMyVPNServerConfigByType(proto.VPNServerConfigTypeAddressPool)
	for _, pool := range poolConf {
		var poolConfig proto.AddressPoolConfig
		err = json.Unmarshal([]byte(pool.Value), &poolConfig)
		if err != nil {
			log.Println("[ERROR] decode pool:", pool.Attr, " config:", pool.Value, ", err:", err.Error())
			continue
		}
		err = UpdateIPAddressPoolToMap(pool.Attr, poolConfig)
	}
	return nil
}

func UpdateIPAddressPoolToMap(name string, poolConfig proto.AddressPoolConfig) (err error) {
	ipAllocator, err2 := NewIPAllocator(&poolConfig.IPv4AddressPool, &poolConfig.IPv6AddressPool)
	if err2 != nil {
		log.Println("[ERROR] get ip allocator:", name, ", err:", err.Error())
		return nil
	}
	GlobalAddressPoolAllocatorMap.mutex.Lock()
	GlobalAddressPoolAllocatorMap.PoolMap[name] = ipAllocator
	GlobalAddressPoolAllocatorMap.mutex.Unlock()
	return nil
}

// IPPool is a thread-safe IP address pool.
// All fields are private; use New() to construct and public methods to interact.
type IPPool struct {
	mu    sync.Mutex
	start uint32 // first IP in the pool (network byte order)
	end   uint32 // last IP in the pool (inclusive)
	count uint32 // total IPs = end - start + 1

	prefix int // CIDR prefix length (informational / validation)

	allocated []uint64 // bitmap: bit=1 means allocated
	reserved  []uint64 // bitmap: bit=1 means reserved (bound to at least one user)

	// userID → list of reserved IPs for that user
	// Uses []uint32 (not map[uint32]struct{}) for lower memory overhead.
	userReserved map[int][]uint32

	nextHint uint32 // heuristic: where to resume scanning for free IPs
}

// New creates an IPPool.
//
// Parameters:
//   - startIP, endIP: inclusive IP range defining the pool
//   - prefix: CIDR prefix length (e.g., 24 for /24)
//   - bindings: userID → list of reserved IPs (many-to-many; pass the same IP in
//     multiple users' lists for shared reservations)
func New(startIP, endIP net.IP, prefix int, bindings map[int][]net.IP) (*IPPool, error) {
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)

	if start == 0 || end == 0 {
		return nil, fmt.Errorf("only IPv4 is supported")
	}
	if start > end {
		return nil, fmt.Errorf("start IP (%s) must be <= end IP (%s)", startIP, endIP)
	}

	count := end - start + 1
	words := (int(count) + 63) / 64

	p := &IPPool{
		start:        start,
		end:          end,
		count:        count,
		prefix:       prefix,
		allocated:    make([]uint64, words),
		reserved:     make([]uint64, words),
		userReserved: make(map[int][]uint32),
	}

	for userID, ips := range bindings {
		for _, ip := range ips {
			u := ipToUint32(ip)
			if u == 0 {
				return nil, fmt.Errorf("invalid IPv4 address in bindings for user %d: %s", userID, ip)
			}
			if u < start || u > end {
				return nil, fmt.Errorf("IP %s (user %d) is outside pool range [%s, %s]",
					ip, userID, startIP, endIP)
			}
			idx := u - start
			setBit(p.reserved, idx)
			p.userReserved[userID] = append(p.userReserved[userID], u)
		}
	}

	return p, nil
}

// Allocate assigns a free IP to userID.
//
// Priority:
//  1. The user's own reserved IPs (if any are free)
//  2. Any unallocated, unreserved IP from the general pool
//
// Returns an error if no suitable IP is available.
func (p *IPPool) Allocate(userID int) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// ---- phase 1: try the user's reserved IPs ----
	if reserved, ok := p.userReserved[userID]; ok {
		for _, ipUint := range reserved {
			idx := ipUint - p.start
			if !isSet(p.allocated, idx) {
				setBit(p.allocated, idx)
				return uint32ToIP(ipUint), nil
			}
		}
	}

	// ---- phase 2: scan the general pool ----
	idx, ok := p.scanFree()
	if !ok {
		return nil, fmt.Errorf("pool exhausted: no free IP available")
	}
	setBit(p.allocated, idx)
	p.nextHint = idx + 1
	return uint32ToIP(p.start + idx), nil
}

// AllocateByIP attempts to allocate a specific IP to userID.
//
// The request succeeds when:
//  1. The IP is inside the pool range
//  2. The IP is not already allocated
//  3. The IP is either unreserved, or reserved for userID (including shared)
//
// Returns the allocated IP on success, or an error describing why it failed.
func (p *IPPool) AllocateByIP(userID int, ip net.IP) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	u := ipToUint32(ip)
	if u == 0 {
		return nil, fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	if u < p.start || u > p.end {
		return nil, fmt.Errorf("IP %s is outside pool range [%s, %s]",
			ip, uint32ToIP(p.start), uint32ToIP(p.end))
	}

	idx := u - p.start

	// Already allocated?
	if isSet(p.allocated, idx) {
		return nil, fmt.Errorf("IP %s is already allocated", ip)
	}

	// If the IP is reserved, ensure userID is among the reserving users.
	if isSet(p.reserved, idx) {
		if !p.userReservesIP(userID, u) {
			return nil, fmt.Errorf("IP %s is reserved for other users", ip)
		}
	}

	setBit(p.allocated, idx)
	return uint32ToIP(u), nil
}

// userReservesIP reports whether userID has a reservation for the given IP.
// Must be called while holding p.mu.
func (p *IPPool) userReservesIP(userID int, u uint32) bool {
	for _, v := range p.userReserved[userID] {
		if v == u {
			return true
		}
	}
	return false
}

// Release returns a previously allocated IP to the pool.
// It is safe to call Release on an already-free IP (no-op, no error).
func (p *IPPool) Release(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	u := ipToUint32(ip)
	if u == 0 {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	if u < p.start || u > p.end {
		return fmt.Errorf("IP %s is outside pool range", ip)
	}

	clearBit(p.allocated, u-p.start)
	return nil
}

// AddBinding registers a new user→IP binding. The IP will be reserved for this
// user and excluded from the general pool. Safe to call concurrently.
func (p *IPPool) AddBinding(userID int, ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	u := ipToUint32(ip)
	if u == 0 {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	if u < p.start || u > p.end {
		return fmt.Errorf("IP %s is outside pool range", ip)
	}

	idx := u - p.start
	setBit(p.reserved, idx)
	p.userReserved[userID] = append(p.userReserved[userID], u)
	return nil
}

// RemoveBinding removes a user→IP binding. The IP returns to the general pool
// (unless still bound to another user).
func (p *IPPool) RemoveBinding(userID int, ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	u := ipToUint32(ip)
	if u == 0 {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	list, ok := p.userReserved[userID]
	if !ok {
		return fmt.Errorf("user %d has no bindings", userID)
	}

	// Remove from the user's list
	found := false
	n := 0
	for _, v := range list {
		if v == u {
			found = true
			continue
		}
		list[n] = v
		n++
	}
	if !found {
		return fmt.Errorf("IP %s is not bound to user %d", ip, userID)
	}
	p.userReserved[userID] = list[:n]
	if len(p.userReserved[userID]) == 0 {
		delete(p.userReserved, userID)
	}

	// If no other user still reserves this IP, clear the reserved bit
	if !p.isIPReservedByAnyone(u) {
		clearBit(p.reserved, u-p.start)
	}

	return nil
}

// IsAllocated reports whether an IP is currently allocated.
func (p *IPPool) IsAllocated(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	u := ipToUint32(ip)
	if u < p.start || u > p.end {
		return false
	}
	return isSet(p.allocated, u-p.start)
}

// Stats returns current pool statistics.
func (p *IPPool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()

	var s Stats
	s.Total = p.count
	var i uint32
	for ; i < p.count; i++ {
		alloc := isSet(p.allocated, i)
		resv := isSet(p.reserved, i)
		switch {
		case alloc:
			s.Allocated++
		case resv:
			s.Reserved++
		default:
			s.Free++
		}
	}
	return s
}

// Stats is a snapshot of pool usage.
type Stats struct {
	Total     uint32
	Allocated uint32
	Reserved  uint32
	Free      uint32
}

func (s Stats) String() string {
	return fmt.Sprintf("total=%d allocated=%d reserved=%d free=%d",
		s.Total, s.Allocated, s.Reserved, s.Free)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// scanFree finds an index where allocated=0 AND reserved=0, using
// bits.TrailingZeros64 to skip whole words at a time.  Returns (index, true)
// or (0, false) when the pool is fully exhausted.
func (p *IPPool) scanFree() (uint32, bool) {
	nWords := uint32(len(p.allocated))
	startWord := p.nextHint / 64

	for w := uint32(0); w < nWords; w++ {
		wordIdx := (startWord + w) % nWords

		// free-in-this-word = NOT (allocated OR reserved)
		avail := ^(p.allocated[wordIdx] | p.reserved[wordIdx])
		if avail == 0 {
			continue
		}

		bitIdx := uint32(bits.TrailingZeros64(avail))
		global := wordIdx*64 + bitIdx
		if global < p.count {
			return global, true
		}
	}
	return 0, false
}

// isIPReservedByAnyone checks whether any user still reserves the given IP.
// Must be called while holding p.mu.
func (p *IPPool) isIPReservedByAnyone(ip uint32) bool {
	for _, list := range p.userReserved {
		for _, v := range list {
			if v == ip {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Bitmap primitives (no bounds checks — caller must ensure idx is valid)
// ---------------------------------------------------------------------------

func isSet(bm []uint64, idx uint32) bool {
	return bm[idx/64]&(1<<(idx%64)) != 0
}

func setBit(bm []uint64, idx uint32) {
	bm[idx/64] |= 1 << (idx % 64)
}

func clearBit(bm []uint64, idx uint32) {
	bm[idx/64] &^= 1 << (idx % 64)
}

// ---------------------------------------------------------------------------
// IP ↔ uint32 conversion (big-endian / network byte order)
// ---------------------------------------------------------------------------

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b)
}

// ---------------------------------------------------------------------------
// AddressPool — configuration types for constructing an IPAllocator
// ---------------------------------------------------------------------------

// UserIDBindIP is a user→IP binding from configuration.
type UserIDBindIP struct {
	UserID int    `json:"user_id" form:"user_id"`
	BindIP string `json:"bind_ip" form:"bind_ip"`
}
// ---------------------------------------------------------------------------
// IPAllocator — unified IPv4 + IPv6 allocator
// ---------------------------------------------------------------------------

// IPAllocator combines an IPv4 and an IPv6 pool into a single dual-stack
// allocator. Either pool may be nil (single-stack mode).
type IPAllocator struct {
	v4 *IPPool
	v6 *IPPool6
}

// AllocatorMap is a thread-safe registry of named IPAllocators.
type AllocatorMap struct {
	mu      sync.Mutex
	PoolMap map[string]*IPAllocator
}


// NewIPAllocator creates an IPAllocator from the given pool configs.
// Either ipv4Pool or ipv6Pool may be nil.
func NewIPAllocator(ipv4Pool, ipv6Pool *proto.AddressPool) (*IPAllocator, error) {
	ipa := &IPAllocator{}

	if ipv4Pool != nil && ipv4Pool.StartIP != "" {
		startIP := net.ParseIP(ipv4Pool.StartIP)
		endIP := net.ParseIP(ipv4Pool.EndIP)
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IPv4 pool IPs: start=%s end=%s", ipv4Pool.StartIP, ipv4Pool.EndIP)
		}

		bindings := addressPoolBindings(ipv4Pool)
		v4, err := New(startIP, endIP, ipv4Pool.Prefix, bindings)
		if err != nil {
			return nil, fmt.Errorf("IPv4 pool: %w", err)
		}
		ipa.v4 = v4
	}

	if ipv6Pool != nil && ipv6Pool.StartIP != "" {
		startIP := net.ParseIP(ipv6Pool.StartIP)
		endIP := net.ParseIP(ipv6Pool.EndIP)
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IPv6 pool IPs: start=%s end=%s", ipv6Pool.StartIP, ipv6Pool.EndIP)
		}

		bindings := addressPoolBindings(ipv6Pool)
		v6, err := New6(startIP, endIP, ipv6Pool.Prefix, bindings)
		if err != nil {
			return nil, fmt.Errorf("IPv6 pool: %w", err)
		}
		ipa.v6 = v6
	}

	if ipa.v4 == nil && ipa.v6 == nil {
		return nil, fmt.Errorf("at least one of IPv4 or IPv6 pool must be configured")
	}

	return ipa, nil
}

// addressPoolBindings converts AddressPool.IPBind entries to the
// map[int][]net.IP format expected by New / New6.
func addressPoolBindings(pool *proto.AddressPool) map[int][]net.IP {
	if len(pool.IPBind) == 0 {
		return nil
	}
	bindings := make(map[int][]net.IP)
	for _, b := range pool.IPBind {
		ip := net.ParseIP(b.BindIP)
		if ip == nil {
			continue
		}
		bindings[b.UserID] = append(bindings[b.UserID], ip)
	}
	return bindings
}

// ---------------------------------------------------------------------------
// IPAllocator methods
// ---------------------------------------------------------------------------

// AllocateIP allocates an IP from both the IPv4 and IPv6 pools for the given
// user. Either return value may be nil if that family is not configured, the
// pool is exhausted, or an error occurred.
func (a *IPAllocator) AllocateIP(userID int) (ipv4, ipv6 net.IP, err error) {
	var err6 error
	if a.v4 != nil {
		ipv4, err = a.v4.Allocate(userID)
		if err != nil {
			ipv4 = nil
		}
	}
	if a.v6 != nil {
		ipv6, err6 = a.v6.Allocate(userID)
		if err6 != nil {
			ipv6 = nil
		}
	}
	if ipv4 == nil && ipv6 == nil {
		if err != nil {
			return nil, nil, err
		}
		if err6 != nil {
			return nil, nil, err6
		}
		return nil, nil, fmt.Errorf("both IPv4 and IPv6 pools exhausted or unavailable")
	}
	return ipv4, ipv6, nil
}

// AllocateByIP attempts to allocate a specific IP to userID. It routes to the
// correct sub-pool based on whether the IP is IPv4 or IPv6.
func (a *IPAllocator) AllocateByIP(userID int, ip net.IP) (net.IP, error) {
	if ip.To4() != nil {
		if a.v4 == nil {
			return nil, fmt.Errorf("no IPv4 pool configured")
		}
		return a.v4.AllocateByIP(userID, ip)
	}
	if a.v6 == nil {
		return nil, fmt.Errorf("no IPv6 pool configured")
	}
	return a.v6.AllocateByIP(userID, ip)
}

// ReleaseIP returns a previously allocated IP to its pool. It routes to the
// correct sub-pool (v4 or v6) automatically.
func (a *IPAllocator) ReleaseIP(ip net.IP) error {
	if ip.To4() != nil {
		if a.v4 == nil {
			return fmt.Errorf("no IPv4 pool configured for release: %s", ip)
		}
		return a.v4.Release(ip)
	}
	if a.v6 == nil {
		return fmt.Errorf("no IPv6 pool configured for release: %s", ip)
	}
	return a.v6.Release(ip)
}

// AddUseIP marks an IP as in-use (allocated) without a specific user binding
// check. It delegates to AllocateByIP with userID=0 and silently ignores
// errors (matching old behaviour).
func (a *IPAllocator) AddUseIP(ip net.IP) {
	if ip == nil {
		return
	}
	if ip.To4() != nil {
		if a.v4 != nil {
			if _, err := a.v4.AllocateByIP(0, ip); err != nil {
				// Already allocated or out of range — silently ignore
			}
		}
		return
	}
	if a.v6 != nil {
		if _, err := a.v6.AllocateByIP(0, ip); err != nil {
			// Already allocated or out of range — silently ignore
		}
	}
}

// AddUseIPByStr parses ipStr as a v4 or v6 address and marks it in-use.
func (a *IPAllocator) AddUseIPByStr(ipv4Str, ipv6Str string) {
	if ipv4Str != "" {
		a.AddUseIP(net.ParseIP(ipv4Str))
	}
	if ipv6Str != "" {
		a.AddUseIP(net.ParseIP(ipv6Str))
	}
}

// IsAllocated reports whether an IP is currently allocated in its pool.
func (a *IPAllocator) IsAllocated(ip net.IP) bool {
	if ip.To4() != nil {
		if a.v4 == nil {
			return false
		}
		return a.v4.IsAllocated(ip)
	}
	if a.v6 == nil {
		return false
	}
	return a.v6.IsAllocated(ip)
}

// Stats returns the usage statistics for both sub-pools. Either return value
// is a zero value when that family is not configured.
func (a *IPAllocator) Stats() (v4 Stats, v6 Stats6) {
	if a.v4 != nil {
		v4 = a.v4.Stats()
	}
	if a.v6 != nil {
		v6 = a.v6.Stats()
	}
	return
}

// BindIP reserves an IP for a user.
func (a *IPAllocator) BindIP(userID int, ip net.IP) error {
	if ip.To4() != nil {
		if a.v4 == nil {
			return fmt.Errorf("no IPv4 pool configured")
		}
		return a.v4.AddBinding(userID, ip)
	}
	if a.v6 == nil {
		return fmt.Errorf("no IPv6 pool configured")
	}
	return a.v6.AddBinding(userID, ip)
}

// UnbindIP removes a user→IP reservation.
func (a *IPAllocator) UnbindIP(userID int, ip net.IP) error {
	if ip.To4() != nil {
		if a.v4 == nil {
			return fmt.Errorf("no IPv4 pool configured")
		}
		return a.v4.RemoveBinding(userID, ip)
	}
	if a.v6 == nil {
		return fmt.Errorf("no IPv6 pool configured")
	}
	return a.v6.RemoveBinding(userID, ip)
}


// ---------------------------------------------------------------------------
// uint128 — 128-bit unsigned integer for IPv6 addresses (big-endian byte order)
// ---------------------------------------------------------------------------

// uint128 represents a 128-bit unsigned integer as two 64-bit words.
// hi is the most significant 64 bits, lo is the least significant.
type uint128 struct {
	hi uint64
	lo uint64
}

// ipToUint128 converts a net.IP to uint128. Returns (zero, false) for non-IPv6.
func ipToUint128(ip net.IP) (uint128, bool) {
	v6 := ip.To16()
	if v6 == nil {
		return uint128{}, false
	}
	return uint128{
		hi: binary.BigEndian.Uint64(v6[0:8]),
		lo: binary.BigEndian.Uint64(v6[8:16]),
	}, true
}

// toIP converts a uint128 back to a 16-byte net.IP.
func (u uint128) toIP() net.IP {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], u.hi)
	binary.BigEndian.PutUint64(b[8:16], u.lo)
	return net.IP(b)
}

// cmp128 returns -1, 0, +1 for a < b, a == b, a > b.
func cmp128(a, b uint128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	default:
		return 0
	}
}

// sub128 returns (a - b) as uint64. Returns (0, false) when a < b or the
// result exceeds math.MaxUint64 (should never happen under prefix ≥ 112).
func sub128(a, b uint128) (uint64, bool) {
	if cmp128(a, b) < 0 {
		return 0, false
	}
	if a.hi == b.hi {
		return a.lo - b.lo, true
	}
	// a.hi > b.hi — with prefix ≥ 112 the hi-delta can only be 1
	if a.hi != b.hi+1 {
		return 0, false
	}
	// diff = 2^64 + a.lo - b.lo; only fits when a.lo < b.lo (borrow)
	if a.lo >= b.lo {
		return 0, false
	}
	return (math.MaxUint64 - b.lo) + a.lo + 1, true
}

// ---------------------------------------------------------------------------
// IPPool6 — thread-safe IPv6 address pool
// ---------------------------------------------------------------------------

// IPPool6 is a thread-safe IPv6 address pool.
//
// Design mirrors IPPool (v4) but works on 128-bit addresses. Only the host
// portion (128 - prefix bits) is allocatable; the network portion remains
// invariant across the pool.
//
// Constraints:
//   - prefix ≥ 112 → at most 2¹⁶ (65536) IPs in the pool
//   - All addresses must lie within the same /prefix subnet
type IPPool6 struct {
	mu     sync.Mutex
	start  uint128 // first IP in the pool
	end    uint128 // last IP in the pool (inclusive)
	count  uint32  // total IPs = end - start + 1 (max 65536)
	prefix int     // CIDR prefix length (≥ 112)

	allocated []uint64 // bitmap: bit=1 means allocated
	reserved  []uint64 // bitmap: bit=1 means reserved (bound to ≥1 user)

	// userID → list of reserved IPs for that user
	userReserved map[int][]uint128

	nextHint uint32 // heuristic: where to resume scanning
}

// New6 creates an IPv6 IPPool6.
//
// Parameters:
//   - startIP, endIP: inclusive IPv6 range defining the pool
//   - prefix: CIDR prefix length (must be ≥ 112)
//   - bindings: userID → list of reserved IPs (many-to-many)
func New6(startIP, endIP net.IP, prefix int, bindings map[int][]net.IP) (*IPPool6, error) {
	if prefix < 112 {
		return nil, fmt.Errorf("IPv6 prefix must be at least 112, got %d", prefix)
	}
	if prefix > 128 {
		return nil, fmt.Errorf("IPv6 prefix cannot exceed 128, got %d", prefix)
	}

	start, ok := ipToUint128(startIP)
	if !ok {
		return nil, fmt.Errorf("invalid start IPv6 address: %s", startIP)
	}
	end, ok := ipToUint128(endIP)
	if !ok {
		return nil, fmt.Errorf("invalid end IPv6 address: %s", endIP)
	}
	if cmp128(start, end) > 0 {
		return nil, fmt.Errorf("start IP (%s) must be <= end IP (%s)", startIP, endIP)
	}

	diff, ok := sub128(end, start)
	if !ok {
		return nil, fmt.Errorf("IP range too large (>= 2^64)")
	}
	count := uint32(diff) + 1 // inclusive
	maxHosts := uint32(1) << (128 - prefix)
	if count > maxHosts {
		return nil, fmt.Errorf("range size %d exceeds prefix /%d capacity %d", count, prefix, maxHosts)
	}

	words := (int(count) + 63) / 64

	p := &IPPool6{
		start:        start,
		end:          end,
		count:        count,
		prefix:       prefix,
		allocated:    make([]uint64, words),
		reserved:     make([]uint64, words),
		userReserved: make(map[int][]uint128),
	}

	for userID, ips := range bindings {
		for _, ip := range ips {
			u, ok2 := ipToUint128(ip)
			if !ok2 {
				return nil, fmt.Errorf("invalid IPv6 address in bindings for user %d: %s", userID, ip)
			}
			if cmp128(u, start) < 0 || cmp128(u, end) > 0 {
				return nil, fmt.Errorf("IP %s (user %d) is outside pool range [%s, %s]",
					ip, userID, startIP, endIP)
			}
			idx, _ := sub128(u, start)
			setBit(p.reserved, uint32(idx))
			p.userReserved[userID] = append(p.userReserved[userID], u)
		}
	}

	return p, nil
}

// ipToIndex returns the bitmap index for an IP, or (0, false) if out of range.
// Must be called while holding p.mu.
func (p *IPPool6) ipToIndex(u uint128) (uint32, bool) {
	idx, ok := sub128(u, p.start)
	if !ok {
		return 0, false
	}
	if uint32(idx) >= p.count {
		return 0, false
	}
	return uint32(idx), true
}

// Allocate assigns a free IP to userID.
//
// Priority:
//  1. The user's own reserved IPs (if any are free)
//  2. Any unallocated, unreserved IP from the general pool
func (p *IPPool6) Allocate(userID int) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Phase 1: try the user's reserved IPs.
	if reserved, ok := p.userReserved[userID]; ok {
		for _, u := range reserved {
			idx, ok2 := p.ipToIndex(u)
			if !ok2 {
				continue
			}
			if !isSet(p.allocated, idx) {
				setBit(p.allocated, idx)
				return u.toIP(), nil
			}
		}
	}

	// Phase 2: scan the general pool.
	idx, ok := p.scanFree()
	if !ok {
		return nil, fmt.Errorf("pool exhausted: no free IP available")
	}
	setBit(p.allocated, idx)
	p.nextHint = idx + 1
	return p.indexToIP(idx), nil
}

// AllocateByIP attempts to allocate a specific IP to userID.
//
// The request succeeds when:
//  1. The IP is inside the pool range
//  2. The IP is not already allocated
//  3. The IP is either unreserved, or reserved for userID (including shared)
func (p *IPPool6) AllocateByIP(userID int, ip net.IP) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := ipToUint128(ip)
	if !ok {
		return nil, fmt.Errorf("invalid IPv6 address: %s", ip)
	}

	idx, ok := p.ipToIndex(u)
	if !ok {
		return nil, fmt.Errorf("IP %s is outside pool range [%s, %s]",
			ip, p.start.toIP(), p.end.toIP())
	}

	if isSet(p.allocated, idx) {
		return nil, fmt.Errorf("IP %s is already allocated", ip)
	}

	if isSet(p.reserved, idx) && !p.userReservesIP(userID, u) {
		return nil, fmt.Errorf("IP %s is reserved for other users", ip)
	}

	setBit(p.allocated, idx)
	return u.toIP(), nil
}

// userReservesIP reports whether userID has a reservation for the given IP.
func (p *IPPool6) userReservesIP(userID int, u uint128) bool {
	for _, v := range p.userReserved[userID] {
		if v == u {
			return true
		}
	}
	return false
}

// Release returns a previously allocated IP to the pool.
// Releasing an already-free IP is a no-op (no error).
func (p *IPPool6) Release(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := ipToUint128(ip)
	if !ok {
		return fmt.Errorf("invalid IPv6 address: %s", ip)
	}

	idx, ok := p.ipToIndex(u)
	if !ok {
		return fmt.Errorf("IP %s is outside pool range", ip)
	}

	clearBit(p.allocated, idx)
	return nil
}

// AddBinding registers a new user→IP binding. The IP will be reserved for this
// user and excluded from the general pool for other users.
func (p *IPPool6) AddBinding(userID int, ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := ipToUint128(ip)
	if !ok {
		return fmt.Errorf("invalid IPv6 address: %s", ip)
	}

	idx, ok := p.ipToIndex(u)
	if !ok {
		return fmt.Errorf("IP %s is outside pool range", ip)
	}

	setBit(p.reserved, idx)
	p.userReserved[userID] = append(p.userReserved[userID], u)
	return nil
}

// RemoveBinding removes a user→IP binding. The IP returns to the general pool
// (unless still bound to another user).
func (p *IPPool6) RemoveBinding(userID int, ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := ipToUint128(ip)
	if !ok {
		return fmt.Errorf("invalid IPv6 address: %s", ip)
	}

	list, exists := p.userReserved[userID]
	if !exists {
		return fmt.Errorf("user %d has no bindings", userID)
	}

	// Remove from the user's list.
	found := false
	n := 0
	for _, v := range list {
		if v == u {
			found = true
			continue
		}
		list[n] = v
		n++
	}
	if !found {
		return fmt.Errorf("IP %s is not bound to user %d", ip, userID)
	}
	p.userReserved[userID] = list[:n]
	if len(p.userReserved[userID]) == 0 {
		delete(p.userReserved, userID)
	}

	// If no other user still reserves this IP, clear the reserved bit.
	if !p.isIPReservedByAnyone(u) {
		idx, _ := p.ipToIndex(u)
		clearBit(p.reserved, idx)
	}

	return nil
}

// IsAllocated reports whether an IP is currently allocated.
func (p *IPPool6) IsAllocated(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	u, ok := ipToUint128(ip)
	if !ok {
		return false
	}
	idx, ok := p.ipToIndex(u)
	if !ok {
		return false
	}
	return isSet(p.allocated, idx)
}

// Stats returns current pool statistics.
func (p *IPPool6) Stats() Stats6 {
	p.mu.Lock()
	defer p.mu.Unlock()

	var s Stats6
	s.Total = p.count
	for i := uint32(0); i < p.count; i++ {
		alloc := isSet(p.allocated, i)
		resv := isSet(p.reserved, i)
		switch {
		case alloc:
			s.Allocated++
		case resv:
			s.Reserved++
		default:
			s.Free++
		}
	}
	return s
}

// Stats6 is a snapshot of IPv6 pool usage.
type Stats6 struct {
	Total     uint32
	Allocated uint32
	Reserved  uint32
	Free      uint32
}

func (s Stats6) String() string {
	return fmt.Sprintf("total=%d allocated=%d reserved=%d free=%d",
		s.Total, s.Allocated, s.Reserved, s.Free)
}

// ---------------------------------------------------------------------------
// Internal helpers (IPPool6)
// ---------------------------------------------------------------------------

// indexToIP returns the IP at bitmap index i (i = ip - start).
func (p *IPPool6) indexToIP(i uint32) net.IP {
	// Reconstruct: start + i
	lo := p.start.lo + uint64(i)
	hi := p.start.hi
	if lo < p.start.lo {
		hi++ // carry
	}
	return uint128{hi: hi, lo: lo}.toIP()
}

// scanFree finds an index where allocated=0 AND reserved=0.
func (p *IPPool6) scanFree() (uint32, bool) {
	nWords := uint32(len(p.allocated))
	if nWords == 0 {
		return 0, false
	}
	startWord := p.nextHint / 64

	for w := uint32(0); w < nWords; w++ {
		wordIdx := (startWord + w) % nWords
		avail := ^(p.allocated[wordIdx] | p.reserved[wordIdx])
		if avail == 0 {
			continue
		}
		bitIdx := uint32(bits.TrailingZeros64(avail))
		global := wordIdx*64 + bitIdx
		if global < p.count {
			return global, true
		}
	}
	return 0, false
}

// isIPReservedByAnyone checks whether any user still reserves the given IP.
func (p *IPPool6) isIPReservedByAnyone(u uint128) bool {
	for _, list := range p.userReserved {
		for _, v := range list {
			if v == u {
				return true
			}
		}
	}
	return false
}
