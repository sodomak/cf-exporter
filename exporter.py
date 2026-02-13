#!/usr/bin/env python3
"""
Cloudflare Prometheus Exporter for Free Tier zones.
Uses httpRequestsAdaptiveGroups GraphQL dataset which is available on all plans.
"""

import os
import sys
import time
import logging
import threading
from datetime import datetime, timezone, timedelta

import requests
from prometheus_client import start_http_server, Gauge, Info

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ZONES = os.environ.get("CF_ZONES", "")  # comma-separated zone IDs, empty = all
CF_ACCOUNTS = os.environ.get("CF_ACCOUNTS", "")  # optional account ID
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
SCRAPE_INTERVAL = int(os.environ.get("SCRAPE_INTERVAL", "60"))
SCRAPE_DELAY = int(os.environ.get("SCRAPE_DELAY", "300"))  # data offset in seconds
MAX_ROLLING = 604800  # 7 days — safe margin under free tier's 691200s hard limit
_requested_window = int(os.environ.get("ROLLING_WINDOW", "86400"))
ROLLING_WINDOW = min(_requested_window, MAX_ROLLING)
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cf-exporter")

GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"
ZONES_URL = "https://api.cloudflare.com/client/v4/zones"

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
LABELS = ["zone"]

zone_requests_total = Gauge(
    "cloudflare_zone_requests_total",
    "Number of requests for zone",
    LABELS,
)
zone_bandwidth_total = Gauge(
    "cloudflare_zone_bandwidth_total",
    "Total bandwidth per zone in bytes",
    LABELS,
)
zone_uniques_total = Gauge(
    "cloudflare_zone_uniques_total",
    "Unique visitors per zone",
    LABELS,
)
zone_requests_cached = Gauge(
    "cloudflare_zone_requests_cached",
    "Number of cached requests for zone",
    LABELS + ["cache_status"],
)
zone_bandwidth_cached = Gauge(
    "cloudflare_zone_bandwidth_cached",
    "Cached bandwidth per zone in bytes",
    LABELS + ["cache_status"],
)
zone_requests_country = Gauge(
    "cloudflare_zone_requests_country",
    "Number of requests for zone per country",
    LABELS + ["country"],
)
zone_bandwidth_country = Gauge(
    "cloudflare_zone_bandwidth_country",
    "Bandwidth per country per zone",
    LABELS + ["country"],
)
zone_requests_status = Gauge(
    "cloudflare_zone_requests_status",
    "Number of requests for zone per HTTP status",
    LABELS + ["status"],
)
zone_requests_ssl_encrypted = Gauge(
    "cloudflare_zone_requests_ssl_encrypted",
    "Number of encrypted requests for zone",
    LABELS + ["ssl"],
)
zone_threats_total = Gauge(
    "cloudflare_zone_threats_total",
    "Threats per zone",
    LABELS,
)
zone_threats_country = Gauge(
    "cloudflare_zone_threats_country",
    "Threats per zone per country",
    LABELS + ["country"],
)

exporter_info = Info("cloudflare_exporter", "Cloudflare exporter metadata")
exporter_info.info({"version": "1.0.0", "tier": "free"})

# ---------------------------------------------------------------------------
# Rolling window metrics (aggregated over ROLLING_WINDOW, e.g. 24h)
# ---------------------------------------------------------------------------
RLABELS = ["zone"]

rolling_requests_total = Gauge(
    "cloudflare_zone_rolling_requests_total",
    "Total requests over rolling window",
    RLABELS,
)
rolling_bandwidth_total = Gauge(
    "cloudflare_zone_rolling_bandwidth_total",
    "Total bandwidth over rolling window in bytes",
    RLABELS,
)
rolling_uniques_total = Gauge(
    "cloudflare_zone_rolling_uniques_total",
    "Unique visitors over rolling window",
    RLABELS,
)
rolling_requests_cached = Gauge(
    "cloudflare_zone_rolling_requests_cached",
    "Cached requests over rolling window",
    RLABELS + ["cache_status"],
)
rolling_bandwidth_cached = Gauge(
    "cloudflare_zone_rolling_bandwidth_cached",
    "Cached bandwidth over rolling window in bytes",
    RLABELS + ["cache_status"],
)
rolling_requests_country = Gauge(
    "cloudflare_zone_rolling_requests_country",
    "Requests per country over rolling window",
    RLABELS + ["country"],
)
rolling_bandwidth_country = Gauge(
    "cloudflare_zone_rolling_bandwidth_country",
    "Bandwidth per country over rolling window in bytes",
    RLABELS + ["country"],
)
rolling_requests_status = Gauge(
    "cloudflare_zone_rolling_requests_status",
    "Requests per HTTP status over rolling window",
    RLABELS + ["status"],
)
rolling_requests_ssl = Gauge(
    "cloudflare_zone_rolling_requests_ssl",
    "Requests per SSL protocol over rolling window",
    RLABELS + ["ssl"],
)
rolling_threats_total = Gauge(
    "cloudflare_zone_rolling_threats_total",
    "Threats over rolling window",
    RLABELS,
)
rolling_threats_country = Gauge(
    "cloudflare_zone_rolling_threats_country",
    "Threats per country over rolling window",
    RLABELS + ["country"],
)

exporter_scrape_errors = Gauge(
    "cloudflare_exporter_scrape_errors_total",
    "Total number of scrape errors",
)
exporter_last_scrape = Gauge(
    "cloudflare_exporter_last_scrape_timestamp",
    "Timestamp of last successful scrape",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def cf_headers():
    return {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    }


def discover_zones():
    """Fetch all zones accessible by the token, optionally filtered by CF_ZONES."""
    zones = []
    page = 1
    while True:
        resp = requests.get(
            ZONES_URL, headers=cf_headers(), params={"per_page": 50, "page": page}
        )
        data = resp.json()
        if not data.get("success"):
            log.error("Failed to list zones: %s", data.get("errors"))
            break
        for z in data.get("result", []):
            zones.append({"id": z["id"], "name": z["name"]})
        info = data.get("result_info", {})
        if page >= info.get("total_pages", 1):
            break
        page += 1

    if CF_ZONES:
        allowed = {z.strip() for z in CF_ZONES.split(",")}
        zones = [z for z in zones if z["id"] in allowed]

    for z in zones:
        log.info("Discovered zone: %s %s", z["id"], z["name"])
    return zones


def graphql_query(query, variables):
    """Execute a GraphQL query against Cloudflare's API."""
    resp = requests.post(
        GRAPHQL_URL,
        headers=cf_headers(),
        json={"query": query, "variables": variables},
        timeout=30,
    )
    data = resp.json()
    if data.get("errors"):
        log.error("GraphQL errors: %s", data["errors"])
        return None
    return data.get("data")


# ---------------------------------------------------------------------------
# Scrape queries
# ---------------------------------------------------------------------------
QUERY_TOTALS = """
query($zoneTag: string!, $mintime: Time!, $maxtime: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      totals: httpRequestsAdaptiveGroups(limit: 1, filter: {
        datetime_geq: $mintime, datetime_lt: $maxtime
      }) {
        count
        sum { edgeResponseBytes visits }
      }
    }
  }
}
"""

QUERY_BY_CACHE = """
query($zoneTag: string!, $mintime: Time!, $maxtime: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      byCache: httpRequestsAdaptiveGroups(limit: 50, filter: {
        datetime_geq: $mintime, datetime_lt: $maxtime
      }) {
        count
        sum { edgeResponseBytes }
        dimensions { cacheStatus }
      }
    }
  }
}
"""


QUERY_BY_COUNTRY = """
query($zoneTag: string!, $mintime: Time!, $maxtime: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      byCountry: httpRequestsAdaptiveGroups(limit: 300, filter: {
        datetime_geq: $mintime, datetime_lt: $maxtime
      }) {
        count
        sum { edgeResponseBytes }
        dimensions { clientCountryName }
      }
    }
  }
}
"""

QUERY_BY_STATUS = """
query($zoneTag: string!, $mintime: Time!, $maxtime: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      byStatus: httpRequestsAdaptiveGroups(limit: 100, filter: {
        datetime_geq: $mintime, datetime_lt: $maxtime
      }) {
        count
        dimensions { edgeResponseStatus }
      }
    }
  }
}
"""

QUERY_BY_SSL = """
query($zoneTag: string!, $mintime: Time!, $maxtime: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      bySSL: httpRequestsAdaptiveGroups(limit: 10, filter: {
        datetime_geq: $mintime, datetime_lt: $maxtime
      }) {
        count
        dimensions { clientSSLProtocol }
      }
    }
  }
}
"""

QUERY_THREATS = """
query($zoneTag: string!, $mintime: Time!, $maxtime: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      threats: httpRequestsAdaptiveGroups(limit: 300, filter: {
        datetime_geq: $mintime, datetime_lt: $maxtime,
        edgeResponseStatus: 403
      }) {
        count
        dimensions { clientCountryName }
      }
    }
  }
}
"""


def scrape_zone(zone, mintime, maxtime):
    """Scrape all metrics for a single zone."""
    zone_id = zone["id"]
    zone_name = zone["name"]
    variables = {"zoneTag": zone_id, "mintime": mintime, "maxtime": maxtime}
    log.debug("Scraping zone %s (%s) [%s - %s]", zone_name, zone_id, mintime, maxtime)

    # --- Totals ---
    data = graphql_query(QUERY_TOTALS, variables)
    if data:
        zones = data["viewer"]["zones"]
        if zones:
            groups = zones[0].get("totals", [])
            if groups:
                g = groups[0]
                zone_requests_total.labels(zone=zone_name).set(g["count"])
                zone_bandwidth_total.labels(zone=zone_name).set(
                    g["sum"]["edgeResponseBytes"]
                )
                zone_uniques_total.labels(zone=zone_name).set(g["sum"]["visits"])
                log.info(
                    "Zone %s: %d requests, %d bytes, %d visits",
                    zone_name,
                    g["count"],
                    g["sum"]["edgeResponseBytes"],
                    g["sum"]["visits"],
                )

    # --- By cache status ---
    data = graphql_query(QUERY_BY_CACHE, variables)
    if data and data["viewer"]["zones"]:
        for g in data["viewer"]["zones"][0].get("byCache", []):
            status = g["dimensions"]["cacheStatus"] or "unknown"
            zone_requests_cached.labels(zone=zone_name, cache_status=status).set(
                g["count"]
            )
            zone_bandwidth_cached.labels(zone=zone_name, cache_status=status).set(
                g["sum"]["edgeResponseBytes"]
            )


    # --- By country ---
    data = graphql_query(QUERY_BY_COUNTRY, variables)
    if data and data["viewer"]["zones"]:
        for g in data["viewer"]["zones"][0].get("byCountry", []):
            country = g["dimensions"]["clientCountryName"] or "unknown"
            zone_requests_country.labels(zone=zone_name, country=country).set(
                g["count"]
            )
            zone_bandwidth_country.labels(zone=zone_name, country=country).set(
                g["sum"]["edgeResponseBytes"]
            )

    # --- By HTTP status ---
    data = graphql_query(QUERY_BY_STATUS, variables)
    if data and data["viewer"]["zones"]:
        for g in data["viewer"]["zones"][0].get("byStatus", []):
            status = str(g["dimensions"]["edgeResponseStatus"])
            zone_requests_status.labels(zone=zone_name, status=status).set(g["count"])

    # --- By SSL ---
    data = graphql_query(QUERY_BY_SSL, variables)
    if data and data["viewer"]["zones"]:
        for g in data["viewer"]["zones"][0].get("bySSL", []):
            proto = g["dimensions"]["clientSSLProtocol"] or "none"
            zone_requests_ssl_encrypted.labels(zone=zone_name, ssl=proto).set(
                g["count"]
            )

    # --- Threats (403 responses as proxy for blocked threats) ---
    data = graphql_query(QUERY_THREATS, variables)
    if data and data["viewer"]["zones"]:
        groups = data["viewer"]["zones"][0].get("threats", [])
        total_threats = sum(g["count"] for g in groups)
        zone_threats_total.labels(zone=zone_name).set(total_threats)
        for g in groups:
            country = g["dimensions"]["clientCountryName"] or "unknown"
            zone_threats_country.labels(zone=zone_name, country=country).set(
                g["count"]
            )


def scrape_zone_rolling(zone, rolling_start, rolling_end):
    """Scrape rolling window metrics by chunking into 24h API queries and summing."""
    zone_id = zone["id"]
    zone_name = zone["name"]

    start_dt = datetime.strptime(rolling_start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    end_dt = datetime.strptime(rolling_end, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    chunk_size = timedelta(seconds=86400)  # 24h max per API call

    # Build list of (mintime, maxtime) chunks
    chunks = []
    t = start_dt
    while t < end_dt:
        chunk_end = min(t + chunk_size, end_dt)
        chunks.append((
            t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            chunk_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ))
        t = chunk_end

    log.debug("Rolling scrape %s: %d chunks over [%s - %s]", zone_name, len(chunks), rolling_start, rolling_end)

    # Accumulators
    total_requests = 0
    total_bandwidth = 0
    total_visits = 0
    cache_acc = {}      # {status: {count, bytes}}
    country_acc = {}    # {country: {count, bytes}}
    status_acc = {}     # {status: count}
    ssl_acc = {}        # {proto: count}
    threat_acc = {}     # {country: count}

    for mintime, maxtime in chunks:
        variables = {"zoneTag": zone_id, "mintime": mintime, "maxtime": maxtime}

        # --- Totals ---
        data = graphql_query(QUERY_TOTALS, variables)
        if data and data["viewer"]["zones"]:
            groups = data["viewer"]["zones"][0].get("totals", [])
            if groups:
                g = groups[0]
                total_requests += g["count"]
                total_bandwidth += g["sum"]["edgeResponseBytes"]
                total_visits += g["sum"]["visits"]

        # --- By cache status ---
        data = graphql_query(QUERY_BY_CACHE, variables)
        if data and data["viewer"]["zones"]:
            for g in data["viewer"]["zones"][0].get("byCache", []):
                status = g["dimensions"]["cacheStatus"] or "unknown"
                if status not in cache_acc:
                    cache_acc[status] = {"count": 0, "bytes": 0}
                cache_acc[status]["count"] += g["count"]
                cache_acc[status]["bytes"] += g["sum"]["edgeResponseBytes"]

        # --- By country ---
        data = graphql_query(QUERY_BY_COUNTRY, variables)
        if data and data["viewer"]["zones"]:
            for g in data["viewer"]["zones"][0].get("byCountry", []):
                country = g["dimensions"]["clientCountryName"] or "unknown"
                if country not in country_acc:
                    country_acc[country] = {"count": 0, "bytes": 0}
                country_acc[country]["count"] += g["count"]
                country_acc[country]["bytes"] += g["sum"]["edgeResponseBytes"]

        # --- By HTTP status ---
        data = graphql_query(QUERY_BY_STATUS, variables)
        if data and data["viewer"]["zones"]:
            for g in data["viewer"]["zones"][0].get("byStatus", []):
                s = str(g["dimensions"]["edgeResponseStatus"])
                status_acc[s] = status_acc.get(s, 0) + g["count"]

        # --- By SSL ---
        data = graphql_query(QUERY_BY_SSL, variables)
        if data and data["viewer"]["zones"]:
            for g in data["viewer"]["zones"][0].get("bySSL", []):
                proto = g["dimensions"]["clientSSLProtocol"] or "none"
                ssl_acc[proto] = ssl_acc.get(proto, 0) + g["count"]

        # --- Threats ---
        data = graphql_query(QUERY_THREATS, variables)
        if data and data["viewer"]["zones"]:
            for g in data["viewer"]["zones"][0].get("threats", []):
                country = g["dimensions"]["clientCountryName"] or "unknown"
                threat_acc[country] = threat_acc.get(country, 0) + g["count"]

        # Throttle to avoid API rate limits
        time.sleep(1)

    # --- Set all rolling metrics ---
    rolling_requests_total.labels(zone=zone_name).set(total_requests)
    rolling_bandwidth_total.labels(zone=zone_name).set(total_bandwidth)
    rolling_uniques_total.labels(zone=zone_name).set(total_visits)

    for status, vals in cache_acc.items():
        rolling_requests_cached.labels(zone=zone_name, cache_status=status).set(vals["count"])
        rolling_bandwidth_cached.labels(zone=zone_name, cache_status=status).set(vals["bytes"])

    for country, vals in country_acc.items():
        rolling_requests_country.labels(zone=zone_name, country=country).set(vals["count"])
        rolling_bandwidth_country.labels(zone=zone_name, country=country).set(vals["bytes"])

    for status, count in status_acc.items():
        rolling_requests_status.labels(zone=zone_name, status=status).set(count)

    for proto, count in ssl_acc.items():
        rolling_requests_ssl.labels(zone=zone_name, ssl=proto).set(count)

    total_threats = sum(threat_acc.values())
    rolling_threats_total.labels(zone=zone_name).set(total_threats)
    for country, count in threat_acc.items():
        rolling_threats_country.labels(zone=zone_name, country=country).set(count)

    log.info(
        "Rolling %s: %d requests, %d bytes, %d visits (%d chunks)",
        zone_name, total_requests, total_bandwidth, total_visits, len(chunks),
    )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def scrape_loop():
    """Continuously scrape all zones at SCRAPE_INTERVAL."""
    zones = discover_zones()
    if not zones:
        log.error("No zones found. Check CF_API_TOKEN and CF_ZONES.")
        return

    # Initialize base metrics to 0 so all zones appear in Grafana
    for zone in zones:
        zn = zone["name"]
        zone_requests_total.labels(zone=zn).set(0)
        zone_bandwidth_total.labels(zone=zn).set(0)
        zone_uniques_total.labels(zone=zn).set(0)
        zone_threats_total.labels(zone=zn).set(0)
        rolling_requests_total.labels(zone=zn).set(0)
        rolling_bandwidth_total.labels(zone=zn).set(0)
        rolling_uniques_total.labels(zone=zn).set(0)
        rolling_threats_total.labels(zone=zn).set(0)

    last_rolling_scrape = 0
    # Scale rolling interval based on window size - more chunks = less frequent
    num_chunks = max(1, ROLLING_WINDOW // 86400)
    rolling_interval = max(600, num_chunks * 60)  # at least 10min, ~1min per day of window
    log.info("Rolling scrape interval: %ds (%d day chunks per zone)", rolling_interval, num_chunks)

    while True:
        try:
            now = datetime.now(timezone.utc)
            maxtime = (now - timedelta(seconds=SCRAPE_DELAY)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            mintime = (
                now - timedelta(seconds=SCRAPE_DELAY + SCRAPE_INTERVAL)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

            for zone in zones:
                try:
                    scrape_zone(zone, mintime, maxtime)
                except Exception:
                    log.exception("Error scraping zone %s", zone["name"])
                    exporter_scrape_errors.inc()

            # Rolling window scrape (less frequent to avoid API rate limits)
            if time.time() - last_rolling_scrape >= rolling_interval:
                rolling_max = maxtime
                rolling_min = (
                    now - timedelta(seconds=SCRAPE_DELAY + ROLLING_WINDOW)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                log.info("Running rolling %dh scrape", ROLLING_WINDOW // 3600)
                for zone in zones:
                    try:
                        scrape_zone_rolling(zone, rolling_min, rolling_max)
                    except Exception:
                        log.exception("Error rolling scrape zone %s", zone["name"])
                        exporter_scrape_errors.inc()
                last_rolling_scrape = time.time()

            exporter_last_scrape.set(time.time())
        except Exception:
            log.exception("Error in scrape loop")
            exporter_scrape_errors.inc()

        time.sleep(SCRAPE_INTERVAL)


def main():
    if not CF_API_TOKEN:
        log.error("CF_API_TOKEN is required")
        sys.exit(1)

    log.info("Starting Cloudflare exporter on :%d/metrics", LISTEN_PORT)
    log.info("Scrape interval: %ds, data delay: %ds, rolling window: %dh", SCRAPE_INTERVAL, SCRAPE_DELAY, ROLLING_WINDOW // 3600)
    if _requested_window > MAX_ROLLING:
        log.warning("ROLLING_WINDOW %ds exceeds free tier max, capped to %ds (7 days)", _requested_window, MAX_ROLLING)

    start_http_server(LISTEN_PORT)

    scrape_thread = threading.Thread(target=scrape_loop, daemon=True)
    scrape_thread.start()
    scrape_thread.join()


if __name__ == "__main__":
    main()
