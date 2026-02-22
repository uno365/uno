db.migrate:
	migrate -path ./internal/adapter/db/postgres/migrations -database "$(DATABASE_URL)" up

db.rollback:
	migrate -path ./internal/adapter/db/postgres/migrations -database "$(DATABASE_URL)" down 1

db.migration.create:
	migrate create -ext sql -dir ./internal/adapter/db/postgres/migrations -seq $(name)

test:
	go test ./... -tags=integration -coverprofile=out/coverage.out && go tool cover -html=out/coverage.out -o out/coverage.html