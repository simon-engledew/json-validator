ARG RUST_VERSION=1.63.0

FROM rust:${RUST_VERSION}-slim AS build

RUN apt-get update && apt-get install --no-install-recommends tini

COPY ./ .

RUN cargo build --release

FROM scratch AS root

COPY --from=build /usr/bin/tini /usr/bin/
COPY --from=build ./target/release/json-validator /usr/bin/

FROM gcr.io/distroless/cc

COPY --from=root ./ /

EXPOSE 8080

USER 65534:65534

ENTRYPOINT ["tini", "/usr/bin/json-validator"]
