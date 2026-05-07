/**
 * Lane G — Data443 LLM Gateway
 *
 * Default: GET /health only (safe for shared VPS, no LLM spend).
 * Optional: POST /v1/chat/completions with benign + URL/email-flavored text
 * to exercise policy / classification-related paths when RUN_CHAT_LOAD=true.
 *
 * Env: GATEWAY_BASE_URL (required), PROXY_API_KEY (optional), RUN_CHAT_LOAD, LLM_MODEL
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

const base = (__ENV.GATEWAY_BASE_URL || "").replace(/\/$/, "");
const proxyKey = __ENV.PROXY_API_KEY || "";
const runChat = (__ENV.RUN_CHAT_LOAD || "").toLowerCase() === "true";
const model = __ENV.LLM_MODEL || "gpt-4o-mini";

function headers() {
  const h = { "Content-Type": "application/json" };
  if (proxyKey) {
    h["x-api-key"] = proxyKey;
  }
  return h;
}

export default function () {
  if (!base) {
    failRate.add(1);
    return;
  }

  const hr = http.get(`${base}/health`, { headers: headers() });
  const okHealth = check(hr, {
    "health status 200": (r) => r.status === 200,
  });
  failRate.add(!okHealth);

  if (runChat) {
    const body = JSON.stringify({
      model: model,
      messages: [
        {
          role: "user",
          content:
            "Summarize in one sentence. Links for context: https://example.com/status " +
            "Email: support@example.com — no action required.",
        },
      ],
    });
    const cr = http.post(`${base}/v1/chat/completions`, body, {
      headers: headers(),
      timeout: "120s",
    });
    const okChat = check(cr, {
      "chat status ok": (r) => r.status === 200 || r.status === 401 || r.status === 403,
    });
    failRate.add(!okChat);
  }

  sleep(0.3);
}

export function setup() {
  if (!base) {
    throw new Error("Set GATEWAY_BASE_URL (no trailing slash). Example: http://127.0.0.1:9000");
  }
}
