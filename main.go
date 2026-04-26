package main

import (
	"container/list"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultListenAddr = ":53"
	defaultUpstream   = "192.168.3.1:53"
	defaultCacheLimit = 8 << 20
	timeout           = 2 * time.Second
	fallbackTTL       = 30 * time.Second
	zeroTTL           = time.Second
)

// Common DNS types include A, AAAA, CNAME, NS, SOA, PTR, MX, TXT, SRV, HTTPS,
// SVCB, CAA, DS, DNSKEY, RRSIG, NAPTR, TLSA and more. We only forward the
// small allowlist below; everything else gets a local empty NOERROR reply.
var allowedTypes = map[uint16]struct{}{
	dns.TypeA: {}, dns.TypeCNAME: {}, dns.TypeNS: {}, dns.TypeSOA: {}, dns.TypeSRV: {}, dns.TypeHTTPS: {},
}

type entry struct {
	key     string
	msg     *dns.Msg
	size    int
	expires time.Time
}

type cache struct {
	mu    sync.Mutex
	size  int
	max   int
	ll    *list.List
	items map[string]*list.Element
}

func newCache(max int) *cache {
	return &cache{max: max, ll: list.New(), items: map[string]*list.Element{}}
}

// get returns a copy and marks whether the record is already stale by TTL.
func (c *cache) get(key string) (*dns.Msg, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.items[key]
	if el == nil {
		return nil, false, false
	}
	c.ll.MoveToFront(el)
	it := el.Value.(*entry)
	return it.msg.Copy(), true, time.Now().After(it.expires)
}

// set stores the last full upstream reply and evicts old entries by RAM limit.
func (c *cache) set(key string, msg *dns.Msg) {
	raw, err := msg.Pack()
	if err != nil {
		return
	}
	size := len(key) + len(raw)
	if size > c.max {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	expires := time.Now().Add(minTTL(msg))
	if el := c.items[key]; el != nil {
		it := el.Value.(*entry)
		c.size -= it.size
		it.msg, it.size, it.expires = msg.Copy(), size, expires
		c.size += size
		c.ll.MoveToFront(el)
	} else {
		c.items[key] = c.ll.PushFront(&entry{key: key, msg: msg.Copy(), size: size, expires: expires})
		c.size += size
	}
	for c.size > c.max {
		el := c.ll.Back()
		if el == nil {
			return
		}
		it := el.Value.(*entry)
		delete(c.items, it.key)
		c.size -= it.size
		c.ll.Remove(el)
	}
}

func (c *cache) bytes() int { c.mu.Lock(); defer c.mu.Unlock(); return c.size }

type stats struct {
	total, hits, negativeHits, blocked, refresh, misses, forwarded, errors atomic.Uint64
}

type proxy struct {
	upstream string
	client   *dns.Client
	cache    *cache
	stats    *stats
	flight   sync.Map
}

// ServeDNS applies three rules: block unsupported types, serve cache fast,
// and refresh cached entries in background after replying.
func (p *proxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	p.stats.total.Add(1)
	name, qtype := question(r)
	kind, key := qtypeName(qtype), cacheKey(r)
	if len(r.Question) == 0 || !allowed(qtype) {
		p.replyLocal(w, r, name, kind)
		return
	}
	if msg, ok, stale := p.cache.get(key); ok {
		p.replyCached(w, r, msg, key, name, kind, stale)
		return
	}
	p.replyMiss(w, r, key, name, kind)
}

func (p *proxy) replyLocal(w dns.ResponseWriter, r *dns.Msg, name, kind string) {
	if p.write(w, emptyReply(r), "local", "skip ", name, kind) {
		p.stats.blocked.Add(1)
	}
}

// Cached data wins on latency; stale data is allowed and refreshed later.
func (p *proxy) replyCached(w dns.ResponseWriter, r, msg *dns.Msg, key, name, kind string, stale bool) {
	msg.Id, msg.Response = r.Id, true
	if !p.write(w, msg, "cache", "hit"+negTag(msg)+staleTag(stale), name, kind) {
		return
	}
	if len(msg.Answer) == 0 || msg.Rcode != dns.RcodeSuccess {
		p.stats.negativeHits.Add(1)
	} else {
		p.stats.hits.Add(1)
	}
	go p.refreshCache(key, name, kind, r.Copy())
}

func (p *proxy) replyMiss(w dns.ResponseWriter, r *dns.Msg, key, name, kind string) {
	msg, err := p.exchange(r)
	if err != nil {
		p.stats.errors.Add(1)
		p.stats.misses.Add(1)
		log.Printf("error source=upstream stage=exchange name=%s type=%s err=%v", name, kind, err)
		_ = w.WriteMsg(rcodeReply(r, dns.RcodeServerFailure))
		return
	}
	p.stats.misses.Add(1)
	p.stats.forwarded.Add(1)
	if key != "" && cacheable(msg) {
		p.cache.set(key, msg)
	}
	msg.Id = r.Id
	p.write(w, msg, "upstream", "miss ", name, kind)
}

// Only one background refresh per key runs at a time.
func (p *proxy) refreshCache(key, name, kind string, r *dns.Msg) {
	if key == "" {
		return
	}
	if _, busy := p.flight.LoadOrStore(key, struct{}{}); busy {
		return
	}
	defer p.flight.Delete(key)
	msg, err := p.exchange(r)
	if err != nil {
		p.stats.errors.Add(1)
		log.Printf("error source=refresh stage=exchange name=%s type=%s err=%v", name, kind, err)
		return
	}
	if cacheable(msg) {
		p.cache.set(key, msg)
	}
	p.stats.refresh.Add(1)
	log.Printf("refresh name=%s type=%s rcode=%s answers=%d", name, kind, rcodeName(msg.Rcode), len(msg.Answer))
}

func (p *proxy) exchange(r *dns.Msg) (*dns.Msg, error) {
	msg, _, err := p.client.ExchangeContext(context.Background(), r.Copy(), p.upstream)
	return msg, err
}

func (p *proxy) write(w dns.ResponseWriter, msg *dns.Msg, src, tag, name, kind string) bool {
	if err := w.WriteMsg(msg); err != nil {
		p.stats.errors.Add(1)
		log.Printf("error source=%s stage=write name=%s type=%s rcode=%s err=%v", src, name, kind, rcodeName(msg.Rcode), err)
		return false
	}
	log.Printf("%-5s name=%s type=%s rcode=%s answers=%d", tag, name, kind, rcodeName(msg.Rcode), len(msg.Answer))
	return true
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	addr, upstream, limit := envStr("LISTEN_ADDR", defaultListenAddr), envStr("UPSTREAM_DNS", defaultUpstream), envInt("CACHE_LIMIT_BYTES", defaultCacheLimit)
	if addr == defaultListenAddr && os.Geteuid() != 0 {
		log.Fatalf("run with sudo to bind %s on macOS", addr)
	}
	if addr == defaultListenAddr {
		killPort53Owner()
	}
	p := &proxy{upstream: upstream, client: &dns.Client{Net: "udp", Timeout: timeout}, cache: newCache(limit), stats: &stats{}}
	servers := makeServers(addr, p)
	go printStats(p.stats, p.cache, limit)
	go stopOnSignal(servers...)
	log.Printf("dns cache listening on %s -> %s cache=%d bytes", addr, upstream, limit)
	serve(servers)
}

// Stats are periodic so the request path stays simple and cheap.
func printStats(s *stats, c *cache, limit int) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		log.Printf("stats total=%d hits=%d negative_hits=%d blocked=%d refresh=%d misses=%d forwarded=%d errors=%d cache_used=%d/%d",
			s.total.Load(), s.hits.Load(), s.negativeHits.Load(), s.blocked.Load(), s.refresh.Load(),
			s.misses.Load(), s.forwarded.Load(), s.errors.Load(), c.bytes(), limit)
	}
}

func stopOnSignal(servers ...*dns.Server) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	for _, s := range servers {
		_ = s.Shutdown()
	}
}

// Split IPv4 and IPv6 listeners so replies come back from the same family.
func makeServers(addr string, h dns.Handler) []*dns.Server {
	if addr != defaultListenAddr {
		return []*dns.Server{{Addr: addr, Net: "udp", Handler: h, ReusePort: true, ReuseAddr: true}, {Addr: addr, Net: "tcp", Handler: h, ReusePort: true, ReuseAddr: true}}
	}
	return []*dns.Server{
		{Addr: "0.0.0.0:53", Net: "udp4", Handler: h, ReusePort: true, ReuseAddr: true},
		{Addr: "0.0.0.0:53", Net: "tcp4", Handler: h, ReusePort: true, ReuseAddr: true},
		{Addr: "[::]:53", Net: "udp6", Handler: h, ReusePort: true, ReuseAddr: true},
		{Addr: "[::]:53", Net: "tcp6", Handler: h, ReusePort: true, ReuseAddr: true},
	}
}

// Wait until all servers stop, or exit on the first real listener error.
func serve(servers []*dns.Server) {
	done := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *dns.Server) {
			err := s.ListenAndServe()
			if isClosedErr(err) {
				done <- nil
				return
			}
			done <- err
		}(s)
	}
	left := len(servers)
	for left > 0 {
		if err := <-done; err != nil {
			log.Fatal(err)
		}
		left--
	}
}

func question(r *dns.Msg) (string, uint16) {
	if len(r.Question) == 0 {
		return ".", 0
	}
	return r.Question[0].Name, r.Question[0].Qtype
}

// Cache key follows the DNS question plus EDNS payload shape.
func cacheKey(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	q := r.Question[0]
	var b strings.Builder
	b.WriteString(strings.ToLower(q.Name))
	fmt.Fprintf(&b, "|%d|%d|%t", q.Qtype, q.Qclass, r.CheckingDisabled)
	if opt := r.IsEdns0(); opt != nil {
		fmt.Fprintf(&b, "|%d", opt.UDPSize())
	}
	return b.String()
}

func allowed(qtype uint16) bool   { _, ok := allowedTypes[qtype]; return ok }
func cacheable(msg *dns.Msg) bool { return msg != nil && !msg.Truncated }

// TTL uses the shortest RR TTL; empty answers get a small fallback TTL.
func minTTL(msg *dns.Msg) time.Duration {
	if msg == nil {
		return fallbackTTL
	}
	min, found := uint32(60), false
	for _, group := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range group {
			if rr != nil && (!found || rr.Header().Ttl < min) {
				min, found = rr.Header().Ttl, true
			}
		}
	}
	if !found {
		return fallbackTTL
	}
	if min == 0 {
		return zeroTTL
	}
	return time.Duration(min) * time.Second
}

func emptyReply(r *dns.Msg) *dns.Msg { return rcodeReply(r, dns.RcodeSuccess) }
func rcodeReply(r *dns.Msg, code int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, code)
	m.RecursionAvailable = true
	return m
}
func staleTag(stale bool) string {
	if stale {
		return "*"
	}
	return " "
}
func negTag(msg *dns.Msg) string {
	if len(msg.Answer) == 0 || msg.Rcode != dns.RcodeSuccess {
		return "-"
	}
	return " "
}
func qtypeName(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return fmt.Sprintf("%d", qtype)
}
func rcodeName(code int) string {
	if s, ok := dns.RcodeToString[code]; ok {
		return s
	}
	return fmt.Sprintf("%d", code)
}
func envStr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
func isClosedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}
func envInt(key string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(os.Getenv(key)), "%d", &n); err == nil && n > 0 {
		return n
	}
	return fallback
}

func killPort53Owner() {
	for _, args := range [][]string{{"-ti", "udp:53", "-sUDP:LISTEN"}, {"-ti", "tcp:53", "-sTCP:LISTEN"}} {
		if out, err := exec.Command("lsof", args...).Output(); err == nil {
			for _, pid := range strings.Fields(string(out)) {
				if err := exec.Command("kill", "-9", pid).Run(); err == nil {
					log.Printf("killed process on :53 pid=%s", pid)
				}
			}
		}
	}
}
