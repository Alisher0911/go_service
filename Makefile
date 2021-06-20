tidy:
	go mod tidy
	go mod vendor

run:
	go run ./app/sales-api/main.go

test:
	go test -v ./... -count=1
	staticcheck ./...

runa:
	go run ./app/admin/main.go