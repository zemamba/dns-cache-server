# dns-cache-server

Minimal caching DNS proxy for macOS.

It listens on port `53`, forwards a small allowlist of DNS record types to an upstream resolver, keeps replies in an in-memory LRU cache, serves cached data immediately, and refreshes cached entries in the background.

The project was written for a local MacBook setup with:

- Apple Silicon / macOS
- upstream DNS `192.168.3.1`
- cache size `8 MB`
- local bind on `:53`

## Features

- fast local DNS proxy on `udp4`, `udp6`, `tcp4`, `tcp6`
- in-memory LRU cache limited by RAM usage
- stale-while-refresh behavior
- TTL-aware cache expiration
- negative caching for empty and `NXDOMAIN`-like replies
- local filtering of unsupported record types
- periodic request statistics in terminal
- auto-kill of the process already holding port `53`

## Allowed Record Types

Forwarded upstream:

- `A`
- `CNAME`
- `NS`
- `SOA`
- `SRV`
- `HTTPS`

Answered locally with empty `NOERROR`:

- everything else, including common types such as `AAAA`, `PTR`, `MX`, `TXT`, `SVCB`, `CAA`, `DS`, `DNSKEY`, `RRSIG`, `NAPTR`, `TLSA`

## How It Works

1. If the query type is not in the allowlist, the server returns an empty `NOERROR` reply immediately.
2. If the query is in cache, the cached reply is returned right away.
3. Cached replies are refreshed in the background, one refresh per cache key at a time.
4. If the query is not in cache, it is forwarded to the upstream DNS server.
5. Replies are cached with TTL based on the shortest TTL found in the DNS message.
6. If TTL has expired, stale data may still be served once while the cache is refreshed.

## Cache Policy

- max cache size: `8 MB`
- eviction policy: LRU
- TTL source: minimum TTL across `Answer`, `Authority`, and `Additional`
- fallback TTL for empty replies: `30s`
- zero TTL is normalized to `1s`

## Requirements

- macOS
- Go `1.25+`
- `sudo` access to bind `:53`
- upstream resolver reachable at `192.168.3.1:53`

## Run

```bash
cd "/Users/user/Documents/dns_server_project"
./run.sh
```

`run.sh` builds the binary locally and starts it with `sudo`.

## Test

```bash
go test ./...
go build ./...
```

## Verify

```bash
dig @127.0.0.1 google.com A
dig @::1 -6 google.com A
dig @127.0.0.1 google.com TXT
dig @127.0.0.1 -x 8.8.8.8
```

Expected behavior:

- `A` is forwarded and cached
- `TXT` returns empty locally
- `PTR` returns empty locally

## Example Logs

```text
miss  name=google.com. type=A rcode=NOERROR answers=6
hit   name=google.com. type=A rcode=NOERROR answers=6
hit*  name=google.com. type=A rcode=NOERROR answers=6
skip  name=google.com. type=TXT rcode=NOERROR answers=0
refresh name=google.com. type=A rcode=NOERROR answers=6
stats total=642 hits=121 negative_hits=12 blocked=88 refresh=35 misses=521 forwarded=519 errors=0 cache_used=55794/8388608
```

## Notes

- `dig -6 @127.0.0.1 ...` is not a valid way to test IPv6 transport. Use `@::1 -6`.
- The proxy intentionally does not forward every DNS type.
- This project is intentionally compact and optimized for a local machine, not for public recursive DNS service.

## License

MIT
