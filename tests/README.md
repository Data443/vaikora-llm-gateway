# Test Suite Layout

Clean structure for gateway verification:

- `tests/py/test_all.py`: combined Python pytest suite
- `tests/sh/all.sh`: full automated verification (docker + pytest + API/governance)
- `tests/sh/live.sh`: full verification + interactive live LLM prompt
- `tests/sh/strict_on.sh`: enable strict gateway blocking mode for live demo
- `tests/sh/live_strict.sh`: full verification + strict mode + interactive live prompt
- `tests/run_all_tests.sh`: stable entry command for full verification
- `tests/live_gateway_console.sh`: stable entry command for live testing
- `tests/live_gateway_console_strict.sh`: stable entry command for strict live demo

## Commands

Run full test + governance checks:

```bash
bash tests/run_all_tests.sh
```

Run full verification then interactive live prompt:

```bash
bash tests/live_gateway_console.sh
```

Enable strict gateway blocking mode for live demo (turn on semantic/domain/email/jailbreak/injection + BLOCK actions):

```bash
bash tests/sh/strict_on.sh
```

Run production demo flow (full tests -> strict enable -> live prompt):

```bash
bash tests/live_gateway_console_strict.sh
```

## Logging

- `tests/sh/all.sh` prints full check output and HTTP codes for each step.
- `tests/sh/live.sh` prints raw JSON response plus parsed assistant text.
- `tests/sh/live_strict.sh` prints raw JSON response plus parsed assistant text.
- Set `LIVE_SHOW_RAW=false` to hide raw JSON in live mode.
- Set `ALLOW_LIVE_ON_FAIL=true` to force live prompt even if verification fails.
- Set `RUN_FULL_VERIFY=false` to skip full verification in strict live mode.
- `tests/sh/strict_on.sh` enables provider entitlements based on configured API keys.
- Set `STRICT_ENABLE_ALL_PROVIDERS=true` to force-enable all provider entitlements.

## Extension Pattern

Add future files under these folders:

- Python tests: `tests/py/...`
- Shell runners/utilities: `tests/sh/...`

The runner auto-discovers `tests/py/test_*.py` recursively.


 