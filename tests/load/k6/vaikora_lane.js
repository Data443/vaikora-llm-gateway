/**
 * Lane V — Vaikora (native) HTTP probe
 *
 * Vaikora exposes different routes per deployment. This script hits a single
 * configurable GET path (default /health). Replace VAIKORA_PATH with your
 * team's health or lightweight classifier probe endpoint when available.
 *
 * Env: VAIKORA_BASE_URL (required), VAIKORA_PATH (optional), K6_VUS, K6_DURATION
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

const failRate = new Rate("failed_requests");

export const options = {
  scenarios: {
    steady: {
      executor: "constant-vus",
      vus: Number(__ENV.K6_VUS || 5),
      duration: __ENV.K6_DURATION || "60s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.1"],
    failed_requests: ["rate<0.1"],
    http_req_duration: ["p(95)<8000"],
  },
};

const base = (__ENV.VAIKORA_BASE_URL || "").replace(/\/$/, "");
let path = __ENV.VAIKORA_PATH || "/health";
if (!path.startsWith("/")) {
  path = `/${path}`;
}

export default function () {
  if (!base) {
    failRate.add(1);
    return;
  }

  const url = `${base}${path}`;
  const res = http.get(url);
  const ok = check(res, {
    "GET status < 500": (r) => r.status < 500,
  });
  failRate.add(!ok);
  sleep(0.3);
}

export function setup() {
  if (!base) {
    throw new Error("Set VAIKORA_BASE_URL (no trailing slash).");
  }
}
