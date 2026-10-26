FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY cmd/demo-knox/go.mod cmd/demo-knox/go.sum ./
RUN go mod download
COPY cmd/demo-knox/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /demo-knox .
FROM scratch
COPY --from=build /go/pkg/mod/github.com/pinterest/knox@v0.0.0-20261008214052-61dd58235016/LICENSE /LICENSE.knox
COPY --from=build /demo-knox /demo-knox
USER 65532:65532
ENTRYPOINT ["/demo-knox"]
