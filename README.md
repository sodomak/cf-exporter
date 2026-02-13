# Cloudflare Prometheus Exporter (Free Tier)

A lightweight Prometheus exporter for Cloudflare zone analytics that works with **Free plan** zones.

Most existing exporters (lablabs, Cloudflare's official one) require Pro+ plans. This exporter uses the `httpRequestsAdaptiveGroups` GraphQL dataset, which is available on all plans including Free.

## Metrics

**Per-scrape metrics** (updated every `CF_SCRAPE_INTERVAL`, for time-series graphs):

- `cloudflare_zone_requests_total` — total requests
- `cloudflare_zone_bandwidth_total` — total bandwidth (bytes)
- `cloudflare_zone_uniques_total` — unique visitors
- `cloudflare_zone_requests_cached` / `cloudflare_zone_bandwidth_cached` — by cache status
- `cloudflare_zone_requests_country` / `cloudflare_zone_bandwidth_country` — by country
- `cloudflare_zone_requests_status` — by HTTP status code
- `cloudflare_zone_requests_ssl_encrypted` — by SSL protocol
- `cloudflare_zone_threats_total` / `cloudflare_zone_threats_country` — threats (403 responses)

**Rolling window metrics** (aggregated over `CF_ROLLING_WINDOW`, default 24h, for stat panels and pie charts):

- `cloudflare_zone_rolling_requests_total` / `cloudflare_zone_rolling_bandwidth_total` / `cloudflare_zone_rolling_uniques_total`
- `cloudflare_zone_rolling_requests_cached` / `cloudflare_zone_rolling_bandwidth_cached`
- `cloudflare_zone_rolling_requests_country` / `cloudflare_zone_rolling_bandwidth_country`
- `cloudflare_zone_rolling_requests_status` / `cloudflare_zone_rolling_requests_ssl`
- `cloudflare_zone_rolling_threats_total` / `cloudflare_zone_rolling_threats_country`

Rolling metrics query Cloudflare's full historical data for the configured window, so stat panels show accurate totals immediately — no need to wait for Prometheus to accumulate data.

## Setup

1. Create a Cloudflare API token with **Zone → Analytics → Read** permission.

2. Copy the example env file and add your token:

```bash
cp env-example .env
# edit .env with your CF_API_TOKEN
```

3. Run:

```bash
docker compose up --build -d
```

Metrics are served at `http://localhost:8090/metrics`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CF_API_TOKEN` | required | Cloudflare API token |
| `CF_ZONES` | *(empty = all)* | Comma-separated zone IDs to monitor |
| `CF_EXPORTER_PORT` | `8090` | Metrics endpoint port |
| `CF_SCRAPE_INTERVAL` | `60` | Scrape interval in seconds |
| `CF_SCRAPE_DELAY` | `300` | Data delay offset (Cloudflare analytics lag) |
| `CF_ROLLING_WINDOW` | `86400` | Rolling summary window in seconds (max 691200 = 8 days on free tier) |
| `CF_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `error`) |

## Grafana

Compatible with [Cloudflare dashboard 13133](https://grafana.com/grafana/dashboards/13133-cloudflare/), though some panels that rely on Pro-only fields (content type breakdown) won't have data.

## Why?

Cloudflare's free tier zones have access to `httpRequestsAdaptiveGroups` but **not** `httpRequests1mGroups` or `edgeResponseContentTypeName`. Existing exporters either use the wrong dataset or skip free zones entirely.

## Free tier API limits

- Max **86400s** (24h) per single query — rolling scrapes automatically chunk into daily queries
- Max **691200s** (8 days) historical data — `ROLLING_WINDOW` is capped to this
- Rate limiting kicks in after ~200 rapid requests — rolling scrapes include 1s throttle between calls
