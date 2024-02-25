FROM golang:1.21.5-alpine3.18 AS builder

RUN go version
COPY ./ /github.com/andredubov/sso
WORKDIR /github.com/andredubov/sso

RUN go mod download && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./.bin/app ./cmd/sso/main.go

FROM alpine:3.18.2

RUN apk --no-cache add "ca-certificates=20230506-r0"
WORKDIR /root

COPY --from=builder /github.com/andredubov/sso/.bin/app .
COPY --from=builder /github.com/andredubov/sso/config ./config

CMD [ "./app"]