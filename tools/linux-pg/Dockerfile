FROM rust:1.100-slim
ARG PG_MAJOR=17
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates postgresql-common \
    && /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y \
    && apt-get install -y --no-install-recommends "postgresql-${PG_MAJOR}" \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 fg
ENV RUSTUP_TOOLCHAIN=1.100.0-x86_64-unknown-linux-gnu
USER fg
