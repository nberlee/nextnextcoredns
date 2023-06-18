FROM golang:alpine as gobuild
RUN apk add ca-certificates
ARG GO111MODULE=on
WORKDIR ./src/nextnextcoredns
COPY go.* ./
RUN go mod download

COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o server .

FROM scratch

COPY --from=gobuild /etc/ssl/certs /etc/ssl/certs
COPY --from=gobuild /go/src/nextnextcoredns/server .
CMD ["/server"]

