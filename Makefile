.PHONY: build run test vet vuln race integration generate generate-check fuzz smoke deploy-check up down

build:
	go build -trimpath -o bin/server ./cmd/server
	go build -trimpath -o bin/migrate ./cmd/migrate

run:
	go run ./cmd/server

test:
	go test ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

race:
	go test -race ./...

integration:
	@test -n "$$TEST_DATABASE_URL" || (echo 'Set TEST_DATABASE_URL to an isolated PostgreSQL test database' >&2; exit 1)
	go test -race -tags=integration -count=1 ./...

generate:
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -generate types -package api -o api/types.gen.go api/openapi.yaml

generate-check:
	@tmpfile=$$(mktemp); trap 'rm -f "$$tmpfile"' EXIT; \
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -generate types -package api -o "$$tmpfile" api/openapi.yaml && \
	diff -u api/types.gen.go "$$tmpfile"

fuzz:
	go test ./internal/httpapi -run='^$$' -fuzz=FuzzDecodeObject -fuzztime=20s -parallel=2
	go test ./internal/threat -run='^$$' -fuzz=FuzzNormalizeMD5 -fuzztime=20s -parallel=2

smoke:
	sh scripts/smoke.sh

deploy-check:
	python3 scripts/deploy_check.py

up:
	docker compose up --build -d

down:
	docker compose down
