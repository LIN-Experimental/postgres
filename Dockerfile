# PostgreSQL with the LIN authentication method.
#
# The "lin" method verifies passwords against a tenant REST API and takes its
# whole configuration from the environment, which is why the build below turns
# on libcurl support:
#
#	docker build -t linplatform/postgres .
#	docker run -d --name pg \
#		-e LIN_TENANT=empresa-001 \
#		-e LIN_AUTH_ENDPOINT=https://auth.miempresa.com/api/auth/login \
#		-e LIN_HTTP_TIMEOUT=5000 \
#		-p 5432:5432 linplatform/postgres

###############################################################################
# Build stage
###############################################################################
FROM debian:bookworm-slim AS build

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		bison \
		flex \
		gcc \
		libc6-dev \
		libcurl4-openssl-dev \
		libicu-dev \
		libreadline-dev \
		libssl-dev \
		make \
		perl \
		pkg-config \
		zlib1g-dev \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/postgres
COPY . .

# A build context coming from a Windows checkout (git core.autocrlf=true) has
# CRLF line endings, which turns every "#!/bin/sh" into a request for the
# non-existent interpreter "/bin/sh\r", and carries no executable bits.  Fix
# both before configuring.  Only text files are touched, and the image builds
# binaries rather than running the regression tests, so test data that wants
# CRLF does not matter here.
RUN grep -rlI --null -e "$(printf '\r')" . | xargs -0 -r sed -i 's/\r$//' \
	&& find . -type f \
		\( -name configure -o -name '*.sh' -o -name install-sh \
		   -o -name missing -o -name mkinstalldirs -o -name prep_buildtree \) \
		-exec chmod +x {} +

# --with-libcurl is what makes the "lin" method available; without it
# pg_hba.conf rejects the method as unsupported by the build.
RUN ./configure \
		--prefix=/usr/local/pgsql \
		--with-libcurl \
		--with-openssl \
		--with-icu \
		--with-readline \
		--with-zlib

RUN make -j"$(nproc)" world-bin
RUN make install-world-bin

# Keep the runtime image smaller.  strip complains about anything that is not
# an object file, which is not a build failure.
RUN find /usr/local/pgsql/bin /usr/local/pgsql/lib -type f \
		-exec strip --strip-unneeded {} + || true

###############################################################################
# pgvector
###############################################################################
FROM build AS pgvector

ARG PGVECTOR_VERSION=v0.8.6

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates git \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN git clone --branch "$PGVECTOR_VERSION" --depth 1 \
		https://github.com/pgvector/pgvector.git

# OPTFLAGS="" drops pgvector's default -march=native.  The image has to run on
# machines other than the one that built it, and a native build would die with
# SIGILL the moment it met an older CPU.
RUN cd pgvector \
	&& make OPTFLAGS="" PG_CONFIG=/usr/local/pgsql/bin/pg_config \
	&& make OPTFLAGS="" PG_CONFIG=/usr/local/pgsql/bin/pg_config install \
	&& strip --strip-unneeded /usr/local/pgsql/lib/vector.so

###############################################################################
# Runtime stage
###############################################################################
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="linplatform/postgres" \
	  org.opencontainers.image.description="PostgreSQL with the LIN REST authentication method and pgvector"

ARG DEBIAN_FRONTEND=noninteractive

# ca-certificates is not optional: libcurl needs it to verify the TLS
# certificate of LIN_AUTH_ENDPOINT.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		libcurl4 \
		libicu72 \
		libreadline8 \
		libssl3 \
		locales \
		zlib1g \
	&& rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

ENV LANG=en_US.utf8
ENV PATH=/usr/local/pgsql/bin:$PATH
ENV PGDATA=/var/lib/postgresql/data

# From the pgvector stage, which builds on top of the PostgreSQL install.
COPY --from=pgvector /usr/local/pgsql /usr/local/pgsql

RUN echo /usr/local/pgsql/lib > /etc/ld.so.conf.d/pgsql.conf \
	&& ldconfig \
	&& groupadd -r postgres --gid=999 \
	&& useradd -r -g postgres --uid=999 \
		--home-dir=/var/lib/postgresql --shell=/bin/bash postgres \
	&& mkdir -p "$PGDATA" /var/run/postgresql \
	&& chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql \
	&& chmod 700 "$PGDATA"

COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# The build context may come from a checkout with CRLF line endings.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
	&& chmod 755 /usr/local/bin/docker-entrypoint.sh

VOLUME /var/lib/postgresql/data
EXPOSE 5432
USER postgres

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]
