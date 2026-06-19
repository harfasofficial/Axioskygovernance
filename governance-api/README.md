# Axiosky Governance API

**AI Governance Control Plane** -- Policy enforcement, immutable audit trails, and
human-in-the-loop escalations for regulated AI deployments.

Axiosky sits between your AI agents and the systems they act on. Every agent
action is evaluated against RBI FREE-AI, DPDP Act, and custom compliance rules
before execution. Decisions are logged to a tamper-proof, SHA-256 hash-chained
audit trail.

## Quick Start (Docker)

```bash
git clone https://github.com/harfasofficial/Axioskygovernance.git
cd Axioskygovernance/governance-api
cp .env.example .env          # edit .env with your values
docker-compose up -d          # starts API + Postgres + Redis
python scripts/seed_dev.py    # seeds a test tenant + API key
```

## First API Call

```bash
curl -X POST http://localhost:8000/v1/evaluate \
  -H "Authorization: Bearer axiosky_live_dev_test_key_do_not_use_in_production" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "loan_agent_v1",
    "action_type": "loan_approval",
    "timestamp": "2026-05-01T10:00:00Z",
    "environment": "shadow",
    "payload": {
      "amount": 6000000,
      "customer_id": "CUST_001"
    }
  }'
```

## Using the SDK

```python
from sdk import AxioskyClient

client = AxioskyClient(
    api_key="axiosky_live_your_key_here",
    tenant_id="1",
    base_url="http://localhost:8000",
    environment="shadow",
)

result = client.evaluate(
    agent_id="loan_agent_v1",
    action_type="loan_approval",
    payload={"amount": 5000000, "customer_id": "CUST_001"},
)

print(result.status)
print(result.reason_code)
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/evaluate` | Evaluate an AI action |
| GET | `/v1/audit-logs` | Query audit trail |
| GET | `/v1/audit-logs/verify` | Verify hash chain integrity |
| GET | `/v1/reports/shadow` | Generate shadow mode report |
| GET | `/v1/escalations` | List pending escalations |
| POST | `/v1/escalations/{id}/approve` | Approve escalation |
| POST | `/v1/escalations/{id}/reject` | Reject escalation |

## Architecture

- **Governor**: FastAPI service, request validation, tenant isolation
- **Policy Engine**: JSON rule-based evaluation (RBI FREE-AI, DPDP Act)
- **Audit Service**: SHA-256 hash chain, immutable PostgreSQL with triggers
- **Escalation Service**: Human-in-the-loop workflows with HMAC-signed webhooks

## Running Tests

```bash
docker-compose up -d db redis
pytest tests/ -v
```

## Provisioning a New Tenant

```bash
python scripts/provision_tenant.py "Client Bank Pvt Ltd"
```

## Security

- API keys: SHA-256 hashed, never stored plaintext
- Audit log: PostgreSQL trigger prevents UPDATE/DELETE
- Hash chain: Each entry links to previous via SHA-256
- Tenant isolation: Enforced at API, ORM, and database layers
- SSRF protection: Context hooks validated against private IP ranges
- Webhook signing: HMAC-SHA256 signature on all escalation webhooks

## Deployment Notes

- Set `AXIOSKY_PUBLIC_BASE_URL` explicitly in every deployed environment; do not rely on localhost defaults.
- Set `AUDIT_WRITE_MODE=sync` for bank/NBFC pilots where durability matters more than latency.
- Use `AUDIT_WRITE_MODE=async` only for playground/dev setups where best-effort audit writes are acceptable.

## Environment Variables

See `.env.example` for all configuration options.

## License

Proprietary -- Axiosky Technologies Pvt Ltd
