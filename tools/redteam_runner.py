#!/usr/bin/env python3
"""Run a red-team prompt suite against the gateway."""

import json
import os
import time
from datetime import datetime

import httpx

TOOLS_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(TOOLS_DIR, ".."))
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")
MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
TIMEOUT = float(os.environ.get("REDTEAM_TIMEOUT", "30"))


def load_prompts(path):
    prompts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            prompts.append(json.loads(line))
    return prompts


def resolve_prompts_path():
    candidates = []
    env_path = os.environ.get("REDTEAM_PROMPTS")
    if env_path:
        candidates.append(env_path)
    candidates.append(os.path.join(TOOLS_DIR, "redteam_prompts.jsonl"))
    candidates.append(os.path.join(ROOT_DIR, "documents", "setup_and_run", "redteam_prompts.jsonl"))

    for path in candidates:
        if path and os.path.isfile(path):
            return path

    raise FileNotFoundError(
        "redteam_prompts.jsonl not found. Checked: "
        + ", ".join([p for p in candidates if p])
    )


def summarize_response(resp_json):
    if not isinstance(resp_json, dict):
        return str(resp_json)[:160]
    if "error" in resp_json:
        msg = resp_json["error"].get("message", "")
        return msg[:200]
    choices = resp_json.get("choices")
    if isinstance(choices, list) and choices:
        msg = choices[0].get("message", {}).get("content", "")
        return (msg or "").strip()[:200]
    return json.dumps(resp_json)[:200]


def main():
    prompts_path = resolve_prompts_path()
    prompts = load_prompts(prompts_path)
    out_path = os.path.join(
        TOOLS_DIR,
        f"redteam_results_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl",
    )

    print("Red-team suite")
    print(f"Gateway: {GATEWAY_URL}")
    print(f"Model: {MODEL}")
    print(f"Prompts: {len(prompts)}")
    print(f"Prompts file: {prompts_path}")
    print("")

    with httpx.Client(timeout=TIMEOUT) as client, open(out_path, "w", encoding="utf-8") as out:
        for idx, p in enumerate(prompts, 1):
            payload = {
                "model": MODEL,
                "messages": [{"role": "user", "content": p["prompt"]}],
            }
            start = time.time()
            try:
                r = client.post(f"{GATEWAY_URL}/v1/chat/completions", json=payload)
                duration_ms = int((time.time() - start) * 1000)
                status = r.status_code
                resp_json = r.json() if r.content else {}
            except Exception as e:
                duration_ms = int((time.time() - start) * 1000)
                status = 0
                resp_json = {"error": {"message": str(e)}}

            outcome = "BLOCK" if status == 403 else "ALLOW"
            summary = summarize_response(resp_json)

            result = {
                "id": p.get("id"),
                "level": p.get("level"),
                "category": p.get("category"),
                "expected": p.get("expected"),
                "status": status,
                "outcome": outcome,
                "duration_ms": duration_ms,
                "summary": summary,
            }
            out.write(json.dumps(result, ensure_ascii=True) + "\n")

            print(
                f"[{idx:02d}/{len(prompts)}] {p.get('id')} | {p.get('level')} | {p.get('category')} | "
                f"status={status} outcome={outcome} | {summary}"
            )

    print("")
    print(f"Saved results: {out_path}")


if __name__ == "__main__":
    main()
