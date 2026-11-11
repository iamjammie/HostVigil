# HostVigil — Platform Specification

The living specification is maintained as a Claude doc:
https://claude.ai/artifact/Vxyf4yTkrT9SB9u9rZm9wa

The standalone HUD prototype (demo data) is published at:
https://claude.ai/artifact/N3pZLYTYLW6NWyfG12jJ7Z

Export the doc to Markdown and replace this file when the spec is frozen for v0.1.

## Validation addendum (2026-11-11)

Data validation was added at every trust boundary after a survey of the other suite repositories; see README → *Data validation*. Decisions:

- Rejected events are acked so a misbehaving agent does not replay them forever; the rejection is recorded per host instead.
- Free-text filters are never interpolated into SQL (PostgreSQL binds, ClickHouse string escaping) and are additionally length-capped.
- Bundle members are restricted to plain relative file names; the importer never honours a path from the archive beyond its basename.
