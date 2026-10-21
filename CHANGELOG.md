# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **Concurrent calls could release one request three times, credit one deposit three times, and pass the monthly cap together.** Every state-changing operation of the book now runs one at a time. (The book is a paper simulation; the rules it demonstrates now hold under concurrency.)
