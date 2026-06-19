# Axiosky Shadow Mode Pilot - Terms

## What you get
- 30 days of shadow mode evaluation on your live AI agent traffic.
- Evaluation against RBI FREE-AI, DPDP Act, and custom governance rules already implemented in the product.
- A structured Day 30 report showing every action that would have been blocked or escalated, with the rule, reason, and timestamp.

## What it costs
- Nothing. The 30-day shadow mode pilot is free.

## What we never do
- Never block, delay, or modify any production action during shadow mode.
- Never store raw payload data; payloads are hashed for audit purposes.
- Never move your source customer data outside your infrastructure through context hooks.

## Integration requirements
- One API key.
- Lightweight SDK or direct API calls from each agent.
- Typical integration time under 4 hours for a clean codebase.

## Data and privacy
- Action payloads are hashed immediately for audit logging.
- Raw customer data remains in your infrastructure.
- Context hooks call your APIs and only the returned decision context is used at evaluation time.

## Shadow mode behavior
- In shadow mode, ESCALATE decisions are recorded in the audit log but no escalation records are created and no webhook is fired. This is by design -- shadow mode never causes side effects.
- The API always returns APPROVE in shadow mode, but the real decision (BLOCK/ESCALATE) is visible in the shadow_result field of the response and in the audit trail.

## What comes next
- If the report surfaces real violations or escalation gaps, we discuss production deployment.
- If the report shows no meaningful value, we stop cleanly.

## Exit
- Pilot can be ended at any time.
- No long-term lock-in.
- No raw customer payload retention.
