#!/usr/bin/env bash
# Phase 1 verification commands (Linux/macOS shell)

docker-compose down
docker-compose up -d --build
docker-compose ps
docker-compose logs gateway --tail=100

curl -s http://localhost:8000/health

# PII block (should return 403)
curl -s -X POST http://localhost:8000/v1/chat/completions -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}'

# Update PII policy to LOG_ONLY
curl -s -X PUT http://localhost:8000/admin/policies/pii -H 'Content-Type: application/json' -d '{"policy_name":"pii_detection","action":"LOG_ONLY"}'

# PII should no longer block (response depends on LLM endpoint)
curl -s -X POST http://localhost:8000/v1/chat/completions -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}'

# Run tests
python -m pytest gateway/test/test_gateway.py -q

# Show HTTP status and response body
curl -s -o /tmp/resp.txt -w "HTTP %{http_code}\n" -X POST http://localhost:8000/v1/chat/completions -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}'
cat /tmp/resp.txt

# Cyren endpoint tests (one-line)
curl -qsXPOST -d $'x-ctch-request-type: classifyip\nx-ctch-pver: 1.0\n\nx-ctch-ip: 8.8.8.8\n' https://try-now-ipreputation.data443.io/ctipd/iprep
curl -qsXPOST -d $'x-ctch-request-type: classifyurl\nx-ctch-pver: 1.0\n\nx-ctch-url: https://example.com\n' https://try-now-urlcat.data443.io/ctwsd/websec

# OpenAI test through gateway (one-line)
curl -s -X POST http://localhost:8000/v1/chat/completions -H 'Content-Type: application/json' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello"}]}'
