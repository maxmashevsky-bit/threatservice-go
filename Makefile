.PHONY: build run generate up down

build:
	go build -trimpath -o bin/server ./cmd/server
	go build -trimpath -o bin/migrate ./cmd/migrate

run:
	go run ./cmd/server

generate:
	go generate ./api

up:
	docker compose up --build -d

down:
	docker compose down
