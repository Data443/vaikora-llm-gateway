#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/data443-llm-gateway

python - <<'PY'
from pathlib import Path

root = Path('.')

verify_path = root / 'documents/setup_and_run/phase2_verify.sh'
verify = verify_path.read_text(encoding='utf-8')
old_verify = 'section "Automated Tests (pytest)"\npython -m pytest -q\n'
new_verify = (
    'section "Automated Tests (pytest)"\n'
    'unset PYTEST_ADDOPTS || true\n'
    'python -m pytest -q --import-mode=importlib tests -o asyncio_default_fixture_loop_scope=function\n'
)
if old_verify in verify:
    verify = verify.replace(old_verify, new_verify)
    verify_path.write_text(verify, encoding='utf-8')

apply_path = root / 'commands/phase2_apply_and_verify_vps.sh'
apply = apply_path.read_text(encoding='utf-8')
old_apply = 'PYTEST_ARGS=(-q --import-mode=importlib)'
new_apply = 'unset PYTEST_ADDOPTS || true\nPYTEST_ARGS=(-q --import-mode=importlib tests -o asyncio_default_fixture_loop_scope=function)'
if old_apply in apply:
    apply = apply.replace(old_apply, new_apply)
    apply_path.write_text(apply, encoding='utf-8')

audit_path = root / 'gateway/integrations/audit.py'
audit = audit_path.read_text(encoding='utf-8')
audit = audit.replace('request_body if request_body else None,', 'self._encode_json_field(request_body),')
audit = audit.replace('attributes or {},', 'self._encode_json_field(attributes or {}),')

if 'def _encode_json_field(self, value: Any) -> Optional[str]:' not in audit:
    marker = '        return value\n\n\n# Global audit logger instance\naudit_logger = AuditLogger()\n'
    helper = (
        '        return value\n\n'
        '    def _encode_json_field(self, value: Any) -> Optional[str]:\n'
        '        """Encode dict/list payloads for asyncpg JSON/JSONB parameters."""\n'
        '        if value is None:\n'
        '            return None\n'
        '        if isinstance(value, str):\n'
        '            return value\n'
        '        try:\n'
        '            return json.dumps(value, ensure_ascii=True)\n'
        '        except Exception:\n'
        '            return json.dumps(str(value), ensure_ascii=True)\n\n\n'
        '# Global audit logger instance\n'
        'audit_logger = AuditLogger()\n'
    )
    if marker in audit:
        audit = audit.replace(marker, helper)

audit_path.write_text(audit, encoding='utf-8')
print('Patched: phase2_verify.sh, phase2_apply_and_verify_vps.sh, gateway/integrations/audit.py')
PY

bash commands/fix_nested_repo_and_verify_vps.sh