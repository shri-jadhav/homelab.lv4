# Evaluation plan

Do not claim a detection accuracy percentage from the included examples alone. The dataset is deliberately small and synthetic.

## Baseline checks

- Re-run `run_tests.ps1` after every rule change.
- Confirm each malicious synthetic scenario triggers its intended detector.
- Confirm the negative-control pair (one failure followed by a normal success) does not alert.
- Add at least three benign scenarios before describing false-positive behavior.
- Track rule ID, scenario, expected outcome, actual outcome, and notes in a results table.

## Next experiments

1. Five rapid failures for one user/source, then six, to test the threshold boundary.
2. Failures spread over six minutes to check the five-minute window.
3. Eight distinct users from one source inside ten minutes, then seven as a negative control.
4. A successful login from a different source to ensure source scoping works as intended.
5. A privilege grant more than fifteen minutes later to test correlation window expiry.
6. Duplicate event ID and malformed timestamp tests.
7. A simulated benign service-desk reset and a shared proxy scenario to examine false positives.

Document each expected result before running the test; that reduces the temptation to adjust the expected outcome to match a bug.
