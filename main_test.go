package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testHandler(memCache *cache, resolver *dns.Client, upstream string, s *stats) dns.HandlerFunc {
	p := &proxy{upstream: upstream, client: resolver, cache: memCache, stats: s}
	return dns.HandlerFunc(p.ServeDNS)
}

func TestCacheHit(t *testing.T) {
	var upstreamCalls atomic.Uint64

	upstreamHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalls.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(1, 2, 3, 4),
		}}
		_ = w.WriteMsg(m)
	})

	upstream := &dns.Server{Addr: "127.0.0.1:15353", Net: "udp", Handler: upstreamHandler}
	go func() { _ = upstream.ListenAndServe() }()
	t.Cleanup(func() { _ = upstream.Shutdown() })
	waitUDP(t, "127.0.0.1:15353")

	memCache := newCache(8 << 20)
	resolver := &dns.Client{Net: "udp", Timeout: time.Second}
	h := testHandler(memCache, resolver, "127.0.0.1:15353", &stats{})

	server := &dns.Server{Addr: "127.0.0.1:10553", Net: "udp", Handler: h}
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	waitUDP(t, "127.0.0.1:10553")

	client := &dns.Client{Net: "udp", Timeout: time.Second}
	query := new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeA)

	for i := 0; i < 2; i++ {
		resp, _, err := client.Exchange(query, "127.0.0.1:10553")
		if err != nil {
			t.Fatalf("exchange %d failed: %v", i+1, err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("unexpected answer count: %d", len(resp.Answer))
		}
	}

	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("expected 1 upstream call, got %d", got)
	}

	time.Sleep(150 * time.Millisecond)
	if got := upstreamCalls.Load(); got < 2 {
		t.Fatalf("expected background refresh after cache hit, got %d upstream calls", got)
	}
}

func TestStaleCacheHitStillRepliesAndRefreshes(t *testing.T) {
	var upstreamCalls atomic.Uint64

	upstreamHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalls.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   net.IPv4(5, 6, 7, 8),
		}}
		_ = w.WriteMsg(m)
	})

	upstream := &dns.Server{Addr: "127.0.0.1:15356", Net: "udp", Handler: upstreamHandler}
	go func() { _ = upstream.ListenAndServe() }()
	t.Cleanup(func() { _ = upstream.Shutdown() })
	waitUDP(t, "127.0.0.1:15356")

	memCache := newCache(8 << 20)
	resolver := &dns.Client{Net: "udp", Timeout: time.Second}
	h := testHandler(memCache, resolver, "127.0.0.1:15356", &stats{})

	server := &dns.Server{Addr: "127.0.0.1:10556", Net: "udp", Handler: h}
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	waitUDP(t, "127.0.0.1:10556")

	client := &dns.Client{Net: "udp", Timeout: time.Second}
	query := new(dns.Msg)
	query.SetQuestion("stale.example.org.", dns.TypeA)

	resp, _, err := client.Exchange(query, "127.0.0.1:10556")
	if err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("unexpected answer count: %d", len(resp.Answer))
	}

	time.Sleep(1100 * time.Millisecond)

	resp, _, err = client.Exchange(query, "127.0.0.1:10556")
	if err != nil {
		t.Fatalf("stale exchange failed: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("unexpected stale answer count: %d", len(resp.Answer))
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("expected stale reply from cache before refresh, got %d upstream calls", got)
	}

	time.Sleep(150 * time.Millisecond)
	if got := upstreamCalls.Load(); got < 2 {
		t.Fatalf("expected refresh after stale hit, got %d upstream calls", got)
	}
}

func TestNegativeCacheHit(t *testing.T) {
	var upstreamCalls atomic.Uint64

	upstreamHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalls.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})

	upstream := &dns.Server{Addr: "127.0.0.1:15354", Net: "udp", Handler: upstreamHandler}
	go func() { _ = upstream.ListenAndServe() }()
	t.Cleanup(func() { _ = upstream.Shutdown() })
	waitUDP(t, "127.0.0.1:15354")

	memCache := newCache(8 << 20)
	resolver := &dns.Client{Net: "udp", Timeout: time.Second}
	h := testHandler(memCache, resolver, "127.0.0.1:15354", &stats{})

	server := &dns.Server{Addr: "127.0.0.1:10554", Net: "udp", Handler: h}
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	waitUDP(t, "127.0.0.1:10554")

	client := &dns.Client{Net: "udp", Timeout: time.Second}
	query := new(dns.Msg)
	query.SetQuestion("empty.example.org.", dns.TypeHTTPS)

	for i := 0; i < 2; i++ {
		resp, _, err := client.Exchange(query, "127.0.0.1:10554")
		if err != nil {
			t.Fatalf("exchange %d failed: %v", i+1, err)
		}
		if len(resp.Answer) != 0 {
			t.Fatalf("unexpected answer count: %d", len(resp.Answer))
		}
	}

	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("expected 1 upstream call before refresh, got %d", got)
	}

	time.Sleep(150 * time.Millisecond)
	if got := upstreamCalls.Load(); got < 2 {
		t.Fatalf("expected background refresh for negative cache hit, got %d upstream calls", got)
	}
}

func TestBlockedTypeReturnsEmptyWithoutUpstream(t *testing.T) {
	var upstreamCalls atomic.Uint64

	upstreamHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalls.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})

	upstream := &dns.Server{Addr: "127.0.0.1:15355", Net: "udp", Handler: upstreamHandler}
	go func() { _ = upstream.ListenAndServe() }()
	t.Cleanup(func() { _ = upstream.Shutdown() })
	waitUDP(t, "127.0.0.1:15355")

	memCache := newCache(8 << 20)
	resolver := &dns.Client{Net: "udp", Timeout: time.Second}
	h := testHandler(memCache, resolver, "127.0.0.1:15355", &stats{})

	server := &dns.Server{Addr: "127.0.0.1:10555", Net: "udp", Handler: h}
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	waitUDP(t, "127.0.0.1:10555")

	client := &dns.Client{Net: "udp", Timeout: time.Second}
	query := new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeTXT)

	resp, _, err := client.Exchange(query, "127.0.0.1:10555")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("unexpected answer count: %d", len(resp.Answer))
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("expected no upstream calls, got %d", got)
	}
}

func waitUDP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("udp server did not start: %s", addr)
}
