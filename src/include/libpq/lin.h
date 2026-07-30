/*-------------------------------------------------------------------------
 *
 * lin.h
 *	  Interface to libpq/auth-lin.c
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/libpq/lin.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_LIN_H
#define PG_LIN_H

/*
 * The LIN method speaks HTTP to an external service, which we do with
 * libcurl, so it is only available in builds that have it.  The autoconf
 * build defines HAVE_LIBCURL for --with-libcurl; the meson build sets
 * USE_LIN_AUTH directly (it reserves USE_LIBCURL for the client-side OAuth
 * flow, which has stricter platform requirements than we do).
 */
#if defined(HAVE_LIBCURL) && !defined(USE_LIN_AUTH)
#define USE_LIN_AUTH 1
#endif

/*
 * Names of the environment variables holding the whole LIN configuration.
 * LIN_TENANT and LIN_AUTH_ENDPOINT are required; LIN_HTTP_TIMEOUT is
 * optional.
 */
#define LIN_ENV_TENANT		"LIN_TENANT"
#define LIN_ENV_ENDPOINT	"LIN_AUTH_ENDPOINT"
#define LIN_ENV_TIMEOUT		"LIN_HTTP_TIMEOUT"

/* Value used when LIN_HTTP_TIMEOUT is not set, in milliseconds */
#define LIN_DEFAULT_TIMEOUT_MS	5000

/*
 * Largest API response we are willing to read.  A cap keeps a hostile or
 * broken service from exhausting our memory; a response longer than this is
 * treated as a failure rather than parsed as far as it goes.
 */
#define LIN_MAX_RESPONSE_SIZE	8192

/*
 * Optional top-level fields of the response.  LIN_AUTH_FIELD, when present,
 * must be the boolean true or the credentials are rejected; LIN_ROLE_FIELD
 * names the database role the connection should assume, instead of the one the
 * client asked for.
 */
#define LIN_AUTH_FIELD			"authenticated"
#define LIN_ROLE_FIELD			"role"

/*
 * How long a successful answer from the API may be reused, in seconds, and the
 * environment variable that overrides it.  Zero disables the cache.
 *
 * A cache trades revocation latency for connection latency: for up to this
 * long, a credential the API has already accepted keeps working even if it has
 * since been revoked.  Keep it short.
 */
#define LIN_ENV_CACHE_TTL		"LIN_CACHE_TTL"
#define LIN_DEFAULT_CACHE_TTL	20

/*
 * Upper bound on the TTL.  Not a technical limit: it exists so that a typo such
 * as writing milliseconds where seconds are expected is rejected at startup
 * instead of silently caching credentials for hours.
 */
#define LIN_MAX_CACHE_TTL		300

/* Number of cached answers held in shared memory */
#define LIN_CACHE_SLOTS			1024

/*
 * LINAuthCacheShmemCallbacks is declared by storage/subsystems.h, which builds
 * the extern list out of storage/subsystemlist.h.
 */

extern void InitializeLINConfig(void);
extern int	lin_authenticate(const char *username, const char *password,
							 char **mapped_role, const char **logdetail);

#endif							/* PG_LIN_H */
