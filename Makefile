VERSION ?= 0.1.0
OUT ?= dist

.PHONY: all agent server hud bundler release test lint vendor validate

all: agent server hud

vendor:            ## run once on a connected machine, commit vendor/ to the artifact store
	cargo vendor vendor && cd hud && pnpm install && pnpm store path

agent:
	cargo build --release --offline --target x86_64-pc-windows-msvc -p hostvigil-agent
	wix build crates/agent/installer/hostvigil-agent.wxs -d Version=$(VERSION) -o $(OUT)/hostvigil-agent-$(VERSION).msi
	signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a $(OUT)/hostvigil-agent-$(VERSION).msi || echo "unsigned build"

server:
	docker build -f deploy/compose/Dockerfile -t hostvigil/server:$(VERSION) .
	docker save hostvigil/server:$(VERSION) | zstd -19 -o $(OUT)/hostvigil-server-$(VERSION).tar.zst

hud:
	cd hud && pnpm install --offline && pnpm build && tar -C dist -cf - . | zstd -19 -o ../$(OUT)/hostvigil-hud-$(VERSION).tar.zst

bundler:
	cargo build --release --offline -p hostvigil-bundler

release: all
	cd $(OUT) && sha256sum * > SHA256SUMS

validate:
	python3 scripts/validate_rules.py
	python3 hud/test/check_hud.py

test:
	cargo test --workspace --offline

lint:
	cargo fmt --all -- --check && cargo clippy --workspace --offline -- -D warnings
