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
#	POSTGRES_USER				default superuser to create (default postgres)
#	POSTGRES_PASSWORD			its password; with LIN enabled this user logs in
#								with it (scram-sha-256) instead of going through
#								the API.  Both are only used when the cluster is
#								first created.
#	POSTGRES_HOST_AUTH_METHOD	host method to use when LIN is not configured
#	RESOURCE					integer id of this resource for the IP validation
#								(default 0)
#	LIN_IP_VALIDATION			"off" removes the IP-validating proxy; postgres
#								then listens on 5432 directly
#	LIN_IP_VALIDATION_URL		overrides the validation API URL (testing)
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

# La validación de IP contra la API de LIN va activa salvo LIN_IP_VALIDATION=off
ip_validation_enabled()
{
	[ "${LIN_IP_VALIDATION:-on}" != "off" ]
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
			# The default user keeps logging in with its own password; the LIN
			# API is only asked about everybody else.  First match wins, so this
			# rule has to come before the catch-all one.
			if [ -n "${POSTGRES_PASSWORD:-}" ]; then
				echo
				echo "# Added by docker-entrypoint.sh: default user"
				printf 'host\tall\t\t"%s"\t\tall\t\t\tscram-sha-256\n' "${POSTGRES_USER//\"/\"\"}"
			fi
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

	if ip_validation_enabled; then
		# RESOURCE se concatena tal cual en el JSON que recibe la API
		RESOURCE="${RESOURCE:-0}"
		if ! [[ "$RESOURCE" =~ ^[0-9]+$ ]]; then
			echo "Error: RESOURCE ('$RESOURCE') debe ser un entero" >&2
			exit 1
		fi
		export RESOURCE

		log "IP validation enabled: proxy on 5432 -> postgres on 5433 (resource=$RESOURCE)"

		# PROXY protocol: la IP real llega en la cabecera del proxy TCP de delante (p. ej. Caddy layer4
		# con "proxy_protocol": "v2"). Con esto activo TODA conexión debe traerla. LIN_TRUSTED_PROXIES
		# lista las IPs desde las que se confía en ella.
		proxy_conf=/etc/lin/nginx.conf
		if [ "${LIN_PROXY_PROTOCOL:-off}" = "on" ]; then
			if [ -z "${LIN_TRUSTED_PROXIES:-}" ]; then
				echo "Error: LIN_PROXY_PROTOCOL=on requiere LIN_TRUSTED_PROXIES (IPs del proxy, separadas por comas)" >&2
				exit 1
			fi
			export LIN_TRUSTED_PROXIES
			proxy_conf=/var/run/openresty/nginx.conf
			sed 's/listen 5432;/listen 5432 proxy_protocol;/' /etc/lin/nginx.conf > "$proxy_conf"
			log "PROXY protocol enabled (trusted proxies: $LIN_TRUSTED_PROXIES)"
		fi

		# PostgreSQL en segundo plano (puerto 5433, por PGPORT) y el proxy de LIN
		# delante. Si cualquiera de los dos muere, el contenedor termina.
		"$@" &
		pg_pid=$!
		/usr/local/openresty/bin/openresty -p /var/run/openresty -c "$proxy_conf" -g 'daemon off;' &
		proxy_pid=$!

		# docker stop: parada rápida de PostgreSQL y cierre ordenado del proxy
		stopping=0
		trap 'stopping=1; kill -INT "$pg_pid" 2>/dev/null || true; kill -QUIT "$proxy_pid" 2>/dev/null || true' INT TERM

		status=0
		wait -n "$pg_pid" "$proxy_pid" || status=$?
		# Una parada pedida (docker stop) es una salida limpia, no el código de la señal
		if [ "$stopping" = 1 ]; then
			status=0
		fi
		kill -INT "$pg_pid" 2>/dev/null || true
		kill -QUIT "$proxy_pid" 2>/dev/null || true
		wait || true
		exit "$status"
	fi

	log "IP validation disabled: postgres listens on 5432"
	export PGPORT=5432
fi

exec "$@"
