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

extern void InitializeLINConfig(void);
extern int	lin_authenticate(const char *username, const char *password,
							 char **mapped_role, const char **logdetail);

#endif							/* PG_LIN_H */
