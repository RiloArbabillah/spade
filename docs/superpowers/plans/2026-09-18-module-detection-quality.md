# Module detection quality plan

## Summary

Implement every open item in `docs/bug-bounty-gaps.md` section 4. The work
reduces false positives, improves coverage for existing vulnerability modules,
keeps runtime dependencies unchanged, and records time-based probes as opt-in.

## Changes

1. Mask credential-like values once when `Exchange` is created, then regression
   check every generated report format.
2. Expand SPA baselines to four probes and use normalized body similarity.
3. Replace SSRF size heuristics with cloud metadata signatures, control-response
   differentials, and the existing OOB collector.
4. Parse reflected XSS context and test encoded variants before reporting.
5. Expand LFI signatures for absolute, encoded, PHP wrapper, proc, and Windows
   paths.
6. Add DBMS-specific SQLi errors and a boolean oracle. Move time-based SQL and
   command probes behind `--timing-probes`.
7. Improve CMDi echo oracles and remove the overly narrow XXE shell check.
8. Centralize payload catalogs with context, oracle, confidence, and safety
   metadata.

## Interfaces

- Add `--timing-probes` (default off).
- Add `timing_probes` to JSON scan metadata.
- Add `SQLI_BOOLEAN`, `SQLI_TIME`, `SSRF_METADATA`, and `SSRF_DIFFERENTIAL`
  finding metadata.
- Preserve existing finding codes and report schemas.

## Verification

- `rtk .venv/bin/pytest -q`
- `rtk .venv/bin/ruff check .`
- `rtk git diff --check`
- End-to-end scans against local fixtures only.

