FROM gcr.io/distroless/base-debian12:nonroot

COPY ./target/x86_64-unknown-linux-musl/release/tappd-simulator /app/tappd-simulator
COPY ./certs/* /app/certs/

EXPOSE 8090

WORKDIR /

USER nonroot:nonroot
ENTRYPOINT ["/app/tappd-simulator", "--key-file", "/app/certs/app.key", "--cert-file", "/app/certs/app.crt", "--listen", "0.0.0.0"]
