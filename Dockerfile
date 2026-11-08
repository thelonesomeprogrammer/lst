# lst in a docker:cli image: lst shells out to git and `docker compose`,
# so the runtime image carries both. The binary is static (musl).

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    && strip target/release/lst

FROM docker:cli
RUN apk add --no-cache git
COPY --from=build /src/target/release/lst /usr/local/bin/lst
ENTRYPOINT ["lst"]
