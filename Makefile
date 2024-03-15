.PHONY:
.SILENT:
.DEFAULT_GOAL := run

IS_SSO_MICROSERVICE_RUNNING := $(shell docker ps --filter name=sso_microservice --filter status=running -aq)
IS_SSO_MICROSERVICE_EXITED := $(shell docker ps --filter name=sso_microservice -aq)
IS_SSO_MICROSERVICE_IMAGE := $(shell docker images --filter=reference="sso_microservice" -aq)

IS_SSO_DATABASE_RUNNING := $(shell docker ps --filter name=sso_database --filter status=running -aq)
IS_SSO_DATABASE_EXITED := $(shell docker ps --filter name=sso_database -aq)

build:
	go mod download && CGO_ENABLED=0 GOOS=$(OS) go build -o ./.bin/sso ./cmd/sso/main.go

run: clean
	docker-compose up --build --detach

stop:
	docker-compose down

clean:
ifneq ($(strip $(IS_SSO_MICROSERVICE_RUNNING)),)
	docker stop $(IS_SSO_MICROSERVICE_RUNNING)
endif

ifneq ($(strip $(IS_SSO_MICROSERVICE_EXITED)),)
	docker rm $(IS_SSO_MICROSERVICE_EXITED)
endif

ifneq ($(strip $(IS_SSO_MICROSERVICE_IMAGE)),)
	docker rmi $(IS_SSO_MICROSERVICE_IMAGE)
endif

ifneq ($(strip $(IS_SSO_DATABASE_RUNNING)),)
	docker stop $(IS_SSO_DATABASE_RUNNING)
endif

ifneq ($(strip $(IS_SSO_DATABASE_EXITED)),)
	docker rm $(IS_SSO_DATABASE_EXITED)
endif

gen-mocks:
	go generate ./...

cover:
	mkdir -p ./.cover
	go test -v -coverprofile ./.cover/cover.out ./...
	go tool cover -html ./.cover/cover.out -o ./.cover/cover.html