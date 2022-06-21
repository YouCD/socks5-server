FROM golang as builder
WORKDIR /go/src/github.com/Snawoot/socks5
ENV GOPROXY https://goproxy.cn,direct

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s' -o ./socks5

FROM scratch
COPY --from=builder /go/src/github.com/Snawoot/socks5/socks5 /
USER 9999:9999
EXPOSE 1080/tcp
ENTRYPOINT ["/socks5"]
