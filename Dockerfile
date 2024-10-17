FROM gcr.io/distroless/cc-debian12:nonroot

COPY ./target/release/tappd-simulator /app/tappd-simulator
COPY ./certs/* /app/certs/

EXPOSE 8090

WORKDIR /

USER nonroot:nonroot
ENTRYPOINT ["/app/tappd-simulator", "--key-file", "/app/certs/app.key", "--cert-file", "/app/certs/app.crt", "--listen", "0.0.0.0"]
