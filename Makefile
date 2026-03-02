APP_NAME=trustpulse
COVERAGE_FILE=coverage.out

.PHONY: build test coverage clean lint

build:
	go build -o bin/$(APP_NAME) ./cmd/trustPulse

test:
	go test ./... -v

coverage:
	go test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	go tool cover -func=$(COVERAGE_FILE)

coverage-html:
	go test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html

lint:
	go vet ./...

clean:
	rm -rf bin $(COVERAGE_FILE) coverage.html