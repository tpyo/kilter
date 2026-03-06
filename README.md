# kilter

> **Note:** Kilter is functionally complete but not yet well tested. Use in production at your own risk.

A high-performance rate-limiting reverse proxy built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora) framework, inspired by [sphinx](https://github.com/Clever/sphinx).

## Crawler-friendly by design

Search engine crawlers are good for your site, but aggressive scrapers are not. Kilter lets you distinguish between them:

- **Built-in IP sets** for Google, Bing, OpenAI (SearchBot, GPTBot, ChatGPT-User), Cloudflare, CloudFront, and Fastly - fetched at startup so you always have current ranges
- **Exclude known crawlers** from rate limits using IP sets or User-Agent patterns
- **Throttle unrecognized bots** with tight limits while leaving verified crawlers unrestricted

## Features

- **Short-lived IP blocks**: Every block carries a TTL. Blocks expire automatically - no manual cleanup, no collateral damage from IP rotation.
- **Crawler-aware IP sets**: Built-in feeds for Google, Bing, OpenAI. Inline CIDR ranges also supported.
- **Multiple rate limiting algorithms**: Sliding Window, Fixed Window, Token Bucket, and GCRA - all implemented as atomic Redis Lua scripts.
- **Distributed**: Multiple kilter instances share state through Redis, so limits and blocks apply consistently across your fleet.
- **Fail-open**: When Redis is unavailable, requests pass through. Your site stays up; you just temporarily lose rate limiting.
- **Flexible matching**: Apply rules by path regex, header patterns, and IP sets. Combine match and exclude conditions.
- **X-Forwarded-For resolution**: Trusted proxy chain parsing so you rate-limit the real client IP, not your load balancer.
- **Observability**: Prometheus metrics, OpenTelemetry tracing, structured logging (default, logfmt, or JSON).

## Quick start

```bash
cargo build --release
```

1. Start Redis: `redis-server`
2. Copy and edit `config.ron` for your environment
3. Run: `./target/release/kilter`

Check health: `curl http://localhost:8081/healthz`
View metrics: `curl http://localhost:8081/metrics`

## Docker

```bash
docker compose up
```

Starts kilter with hot-reload, Redis, a test backend, Grafana, Prometheus, and Tempo.

## References

- [Pingora](https://github.com/cloudflare/pingora) - Cloudflare's proxy framework
- [RON](https://github.com/ron-rs/ron) - Rusty Object Notation

