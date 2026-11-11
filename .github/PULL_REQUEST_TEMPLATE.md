## What

## Why

## Validation
- [ ] `python scripts/validate_rules.py` passes
- [ ] `python hud/test/check_hud.py` passes (if the HUD changed)
- [ ] `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo test --workspace`
- [ ] New inputs (API params, agent event fields, bundle members) have bounds/format checks and a unit test
- [ ] No telemetry or network call added that leaves the air gap
