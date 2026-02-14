db.migrate:
	migrate -path migrations -database "$(DATABASE_URL)" up

db.rollback:
	migrate -path migrations -database "$(DATABASE_URL)" down 1

db.migration.create:
	migrate create -ext sql -dir migrations -seq $(name)

test:
	go test ./... --cover