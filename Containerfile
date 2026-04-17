FROM docker.io/library/golang:1.26 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /multiplexer-proxy-webhook .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /multiplexer-proxy-webhook /multiplexer-proxy-webhook
ENTRYPOINT ["/multiplexer-proxy-webhook"]
