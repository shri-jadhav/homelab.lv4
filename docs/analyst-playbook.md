# Mini analyst playbook

Use this as the consistent process when reviewing each generated alert.

1. **Validate context.** Confirm the host, username, source IP, UTC timestamps, and whether that source could be a corporate VPN, proxy, scanner, or shared egress point.
2. **Reconstruct the timeline.** Follow the alert's `event_ids` in `data/events.jsonl`. Look at events before and after the alert window; an alert is a lead, not proof of compromise.
3. **Check identity controls.** For authentication alerts, check MFA outcome, device posture, sign-in risk, location/source reputation if legitimately available, and account-owner confirmation.
4. **Validate privilege changes.** Confirm role, actor, target account, approval/change ticket, and whether the action was expected. A role name alone does not prove malicious behavior.
5. **Decide and document.** Mark as true positive, benign positive, false positive, or inconclusive in your analyst notes. State exactly what evidence supports the choice.
6. **Contain only with authorization.** If evidence supports compromise, follow the organization's approved process for revoking sessions, disabling accounts, removing privilege, and preserving evidence. This demo does not perform any containment action.
7. **Improve the rule.** Capture false-positive patterns and propose a narrowly scoped exception or a new context requirement. Add regression tests before changing a threshold.

## Suggested case-note template

- Alert ID / rule ID:
- Analyst / review timestamp (UTC):
- Initial classification:
- Entities and time window:
- Evidence reviewed:
- Approved change / business explanation checked:
- Decision and rationale:
- Actions taken (if authorized):
- Detection change proposed:
- Regression test added:
