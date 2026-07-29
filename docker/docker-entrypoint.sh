#!/bin/bash
#
# Entrypoint for the linplatform/postgres image.
#
# On the first start it creates the cluster and, when LIN_TENANT and
# LIN_AUTH_ENDPOINT are present in the environment, sets pg_hba.conf up to
# authenticate host connections with the "lin" method.  On later starts the
# existing cluster is reused untouched.
#
# Recognized variables:
#	LIN_TENANT					tenant owning this instance
#	LIN_AUTH_ENDPOINT			URL of the login API
#	LIN_HTTP_TIMEOUT			API timeout in milliseconds (default 5000)
#	POSTGRES_USER				superuser to create (default postgres)
#	POSTGRES_PASSWORD			superuser password
#	POSTGRES_HOST_AUTH_METHOD	host method to use when LIN is not configured
#
set -Eeuo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"

log()
{
	printf '%s [entrypoint] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" "$*"
}

lin_enabled()
{
	[ -n "${LIN_TENANT:-}" ] && [ -n "${LIN_AUTH_ENDPOINT:-}" ]
}

# Decide how host connections authenticate.  LIN wins when it is configured,
# since that is the whole point of this image.
host_auth_method()
{
	if lin_enabled; then
		echo lin
	elif [ -n "${POSTGRES_HOST_AUTH_METHOD:-}" ]; then
		echo "$POSTGRES_HOST_AUTH_METHOD"
	elif [ -n "${POSTGRES_PASSWORD:-}" ]; then
		echo scram-sha-256
	else
		cat >&2 <<-'EOF'
			Error: cannot decide how to authenticate host connections.

			Set LIN_TENANT and LIN_AUTH_ENDPOINT to authenticate against the LIN
			REST API, or POSTGRES_PASSWORD to use scram-sha-256, or
			POSTGRES_HOST_AUTH_METHOD=trust to accept every connection without
			checking anything (insecure).
		EOF
		exit 1
	fi
}

init_cluster()
{
	local authhost

	authhost="$(host_auth_method)"

	log "creating cluster in $PGDATA (host authentication: $authhost)"

	if [ -n "${POSTGRES_PASSWORD:-}" ]; then
		printf '%s' "$POSTGRES_PASSWORD" |
			initdb -D "$PGDATA" -U "$POSTGRES_USER" --encoding=UTF8 \
				--auth-local=trust --auth-host="$authhost" --pwfile=/dev/stdin
	else
		initdb -D "$PGDATA" -U "$POSTGRES_USER" --encoding=UTF8 \
			--auth-local=trust --auth-host="$authhost"
	fi

	{
		echo
		echo "# Added by docker-entrypoint.sh"
		echo "listen_addresses = '*'"
	} >> "$PGDATA/postgresql.conf"

	# initdb only writes rules for the loopback addresses, so open the cluster
	# up to the rest of the container network as well.
	if lin_enabled; then
		{
			echo
			echo "# Added by docker-entrypoint.sh: LIN authentication"
			printf 'host\tall\t\tall\t\tall\t\t\tlin\n'
		} >> "$PGDATA/pg_hba.conf"
	fi
}

# "postgres --version" and friends print something and exit, so they must not
# drag a cluster into existence first.
wants_help()
{
	local arg

	for arg; do
		case "$arg" in
			-'?' | --help | --describe-config | -V | --version)
				return 0
				;;
		esac
	done

	return 1
}

if [ "${1:-}" = 'postgres' ] && ! wants_help "$@"; then
	if lin_enabled; then
		log "LIN enabled: tenant=$LIN_TENANT endpoint=$LIN_AUTH_ENDPOINT timeout=${LIN_HTTP_TIMEOUT:-5000}ms"
	else
		log "LIN not configured (LIN_TENANT and LIN_AUTH_ENDPOINT are both required)"
	fi

	if [ ! -s "$PGDATA/PG_VERSION" ]; then
		init_cluster
	else
		log "reusing the existing cluster in $PGDATA"
	fi
fi

exec "$@"
