FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
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
