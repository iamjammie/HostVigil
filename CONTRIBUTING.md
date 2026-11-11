# Contributing to HostVigil

Thanks for helping. HostVigil is defensive, offline-first tooling; keep those two properties in every change.

## Before you open a PR

```bash
python scripts/validate_rules.py                 # Sigma / YARA / CIS packs
python hud/test/check_hud.py                     # HUD renders, integrity guard, no overflow
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

CI runs the same set (`.github/workflows/validate.yml`) and must be green.

## Rules of the road

- **Every new input gets a check and a test.** Agent event fields → `hv-ingest/src/validate.rs`. API parameters → `validate_filters` / `is_*` in `hv-api/src/routes.rs`. Bundle contents → `hv-feeds`. HUD data → `checkInvariants()`.
- **Nothing leaves the air gap.** No telemetry, update checks or CDN calls from the agent or server. The HUD may load d3 from cdnjs only because it ships embedded in `hv-api` for production.
- **Signed or refused.** Commands, scripts, updates and feeds are Ed25519-signed; never add a code path that applies unsigned content.
- **Detection rules** go in `rules/` with ATT&CK tags and a false-positive note (use the issue template).
- Commit messages: imperative, one line, body explains *why*.

## Lab

`deploy/lab/` has a Vagrant lab (10 Windows VMs). Phase gates require two weeks without an agent crash on it.
