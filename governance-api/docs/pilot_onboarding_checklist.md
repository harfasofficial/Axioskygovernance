# Axiosky Pilot Onboarding Checklist

## Before kickoff
- [ ] Run `python scripts/provision_tenant.py "Client Name"` to generate pilot API key.
- [ ] Create tenant in database.
- [ ] Confirm technical point of contact.
- [ ] Confirm business owner who will receive the Day 30 report.
- [ ] Set `AXIOSKY_PUBLIC_BASE_URL` to the public URL of your Axiosky deployment.

## Kickoff call
1. Which AI agents are in scope?
2. What does each agent do?
3. Which context hooks are needed, such as watchlist, credit score, or sanctions checks?
4. Are there custom policy rules beyond baseline compliance rules?
5. What defines success for Day 30?
6. Who approves production rollout if the pilot succeeds?

## Integration
- Install SDK or wire direct API calls.
- Send first shadow decision successfully.
- Verify tenant isolation.
- Verify audit logging.
- Configure context hooks if needed.
- Confirm target webhook for escalations.

## During pilot
- Week 1 check-in.
- Week 2 check-in.
- Day 15 midpoint snapshot.
- Day 28 draft report review.
- Day 30 final report and debrief.

## Day 30 debrief
- Which violations were previously unknown?
- Which decisions should have been blocked or escalated?
- Which human approvals are currently missing?
- What regulator or internal audit questions does this now answer?
- What would production rollout need?
