/*-------------------------------------------------------------------------
 *
 * auth-lin.c
 *	  LIN authentication: password verification via an external REST API
 *
 * The LIN method delegates password checking to an HTTP service belonging to
 * the tenant that owns this instance.  Its whole configuration comes from the
 * process environment, so that it can be deployed with nothing but Docker,
 * Kubernetes, or any other platform able to inject environment variables:
 *
 *	LIN_TENANT			tenant owning this instance (required)
 *	LIN_AUTH_ENDPOINT	URL of the login API (required)
 *	LIN_HTTP_TIMEOUT	request timeout in milliseconds (optional, default
 *						LIN_DEFAULT_TIMEOUT_MS)
 *	LIN_CACHE_TTL		how long an acceptance may be reused, in seconds
 *						(optional, default LIN_DEFAULT_CACHE_TTL, 0 disables)
 *
 * Accepted credentials are cached in shared memory for LIN_CACHE_TTL seconds,
 * so that a burst of connections from the same user costs one HTTP round trip
 * rather than one per connection.  The cost is revocation latency: a credential
 * the API has already accepted keeps working for up to that long after being
 * revoked.  Rejections are never cached.
 *
 * The environment is read exactly once per process by InitializeLINConfig(),
 * never once per authentication attempt.  The postmaster calls it during
 * startup when pg_hba.conf uses the method, so that a misconfigured server
 * refuses to start rather than failing every connection, and regular backends
 * inherit the parsed values through fork().  EXEC_BACKEND children do not
 * inherit them, but they do inherit the environment, so they repeat the (still
 * one-time) initialization when they first authenticate a client.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/libpq/auth-lin.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <curl/curl.h>

#include "common/hmac.h"
#include "common/jsonapi.h"
#include "common/sha2.h"
#include "lib/stringinfo.h"
#include "libpq/lin.h"
#include "mb/pg_wchar.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/json.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"

/*
 * Configuration read from the environment, valid for the whole life of the
 * process once lin_config_initialized is set.
 */
typedef struct LINConfig
{
	char	   *tenant;
	char	   *endpoint;
	long		timeout_ms;
	int			cache_ttl;		/* seconds; 0 disables the cache */
} LINConfig;

static LINConfig lin_config;
static bool lin_config_initialized = false;

/* Has curl_global_init() been called in this process? */
static bool lin_curl_initialized = false;

/* Body of an API response, plus whether we had to stop reading it */
typedef struct LINResponse
{
	StringInfoData body;
	bool		truncated;
} LINResponse;

/* Which field's value the parser is about to be handed, if any */
typedef enum LINField
{
	LIN_FIELD_NONE = 0,
	LIN_FIELD_AUTHENTICATED,
	LIN_FIELD_ROLE,
} LINField;

/*
 * State for pulling the fields we care about out of a response.  Only
 * top-level fields count, so the nesting depth has to be tracked.
 */
typedef struct LINResponseParse
{
	int			depth;
	LINField	expecting;		/* whose value comes next */

	bool		auth_seen;		/* was LIN_AUTH_FIELD present? */
	bool		authenticated;	/* ... and was it true? */
	bool		auth_bad_type;	/* ... or was it not a boolean at all? */

	char	   *role;			/* LIN_ROLE_FIELD, or NULL if absent */
	bool		role_bad_type;	/* the role field was not a string */
} LINResponseParse;

/*
 * One cached answer from the API.
 *
 * The credentials are represented only by an HMAC of them, so that a lookup can
 * tell "same user, same password" without the cache holding the password.  The
 * mapped role has to be cached alongside, or a hit would lose the mapping.
 */
typedef struct LINCacheEntry
{
	uint8		digest[PG_SHA256_DIGEST_LENGTH];
	TimestampTz expires;		/* 0 when the slot is unused */
	char		role[NAMEDATALEN];	/* empty string when the API named none */
} LINCacheEntry;

/*
 * The cache itself.  A fixed array of slots addressed by the digest, so a
 * collision simply evicts the previous occupant: entries may be dropped early,
 * but a lookup can never return somebody else's answer.
 *
 * hmac_key is generated once at postmaster startup and shared by every backend.
 * It keeps the digests specific to this cluster's lifetime, so they are not
 * precomputable.
 */
typedef struct LINCacheShared
{
	uint8		hmac_key[PG_SHA256_DIGEST_LENGTH];
	LINCacheEntry entries[LIN_CACHE_SLOTS];
} LINCacheShared;

static LINCacheShared *lin_cache = NULL;

static void lin_curl_init(void);
static size_t lin_response_callback(char *contents, size_t size, size_t nmemb,
									void *userdata);
static bool lin_cache_digest(const char *username, const char *password,
							 uint8 *digest);
static bool lin_cache_lookup(const char *username, const char *password,
							 char **role);
static void lin_cache_store(const char *username, const char *password,
							const char *role);
static void lin_build_request_body(StringInfo body, const char *username,
								   const char *password);
static int	lin_check_response(const LINResponse *response, char **role,
							   const char **logdetail);


/*
 * Shared memory setup for the cache.
 *
 * The area is reserved unconditionally, because pg_hba.conf can start using the
 * "lin" method on a reload, long after shared memory has been sized.  It is
 * small enough that this costs nothing worth measuring.
 */
static void
LINAuthCacheShmemRequest(void *arg)
{
	ShmemRequestStruct(.name = "LIN authentication cache",
					   .size = sizeof(LINCacheShared),
					   .ptr = (void **) &lin_cache);
}

static void
LINAuthCacheShmemInit(void *arg)
{
	memset(lin_cache, 0, sizeof(LINCacheShared));

	if (!pg_strong_random(lin_cache->hmac_key, sizeof(lin_cache->hmac_key)))
		ereport(FATAL,
				(errmsg("could not generate a key for the LIN authentication cache")));
}

const ShmemCallbacks LINAuthCacheShmemCallbacks = {
	.request_fn = LINAuthCacheShmemRequest,
	.init_fn = LINAuthCacheShmemInit,
};

/*
 * Reduce one set of credentials to the digest used as the cache key.
 *
 * The tenant is folded in even though it is fixed for the life of the cluster,
 * so that the digest cannot be meaningful for any other tenant.  The fields are
 * separated by their NUL terminators, so that no two different triples can
 * produce the same input.
 *
 * Returns false if hashing failed, in which case the caller must fall back to
 * asking the API.
 */
static bool
lin_cache_digest(const char *username, const char *password, uint8 *digest)
{
	pg_hmac_ctx *ctx;
	bool		ok = false;

	ctx = pg_hmac_create(PG_SHA256);
	if (ctx == NULL)
		return false;

	if (pg_hmac_init(ctx, lin_cache->hmac_key, sizeof(lin_cache->hmac_key)) == 0 &&
		pg_hmac_update(ctx, (const uint8 *) lin_config.tenant,
					   strlen(lin_config.tenant) + 1) == 0 &&
		pg_hmac_update(ctx, (const uint8 *) username, strlen(username) + 1) == 0 &&
		pg_hmac_update(ctx, (const uint8 *) password, strlen(password) + 1) == 0 &&
		pg_hmac_final(ctx, digest, PG_SHA256_DIGEST_LENGTH) == 0)
		ok = true;

	pg_hmac_free(ctx);

	return ok;
}

/*
 * Which slot a digest belongs in.
 */
static inline uint32
lin_cache_slot(const uint8 *digest)
{
	uint32		hash;

	memcpy(&hash, digest, sizeof(hash));

	return hash % LIN_CACHE_SLOTS;
}

/*
 * Is there a live answer for these credentials?
 *
 * On a hit, *role is set to a palloc'd role name or to NULL if the cached answer
 * named none, and the caller can skip the API entirely.
 */
static bool
lin_cache_lookup(const char *username, const char *password, char **role)
{
	uint8		digest[PG_SHA256_DIGEST_LENGTH];
	LINCacheEntry *entry;
	bool		hit = false;
	char		cached_role[NAMEDATALEN];

	*role = NULL;

	if (lin_config.cache_ttl <= 0 || lin_cache == NULL)
		return false;

	if (!lin_cache_digest(username, password, digest))
		return false;

	entry = &lin_cache->entries[lin_cache_slot(digest)];

	LWLockAcquire(LINAuthCacheLock, LW_SHARED);

	if (entry->expires != 0 &&
		memcmp(entry->digest, digest, PG_SHA256_DIGEST_LENGTH) == 0 &&
		entry->expires > GetCurrentTimestamp())
	{
		hit = true;
		strlcpy(cached_role, entry->role, sizeof(cached_role));
	}

	LWLockRelease(LINAuthCacheLock);

	if (hit && cached_role[0] != '\0')
		*role = pstrdup(cached_role);

	return hit;
}

/*
 * Remember an answer the API gave us.  role may be NULL, meaning the API named
 * no role and the client keeps the one it asked for.
 */
static void
lin_cache_store(const char *username, const char *password, const char *role)
{
	uint8		digest[PG_SHA256_DIGEST_LENGTH];
	LINCacheEntry *entry;

	if (lin_config.cache_ttl <= 0 || lin_cache == NULL)
		return;

	/*
	 * A role we could not store in full would come back truncated on a hit, so
	 * leave the answer uncached instead.  lin_check_response() already rejects
	 * anything this long, so this is belt and braces.
	 */
	if (role != NULL && strlen(role) >= NAMEDATALEN)
		return;

	if (!lin_cache_digest(username, password, digest))
		return;

	entry = &lin_cache->entries[lin_cache_slot(digest)];

	LWLockAcquire(LINAuthCacheLock, LW_EXCLUSIVE);

	memcpy(entry->digest, digest, PG_SHA256_DIGEST_LENGTH);
	if (role != NULL)
		strlcpy(entry->role, role, sizeof(entry->role));
	else
		entry->role[0] = '\0';

	entry->expires = TimestampTzPlusMilliseconds(GetCurrentTimestamp(),
												 lin_config.cache_ttl * 1000L);

	LWLockRelease(LINAuthCacheLock);
}

/*
 * Read the LIN configuration out of the environment.
 *
 * Does nothing if the current process has already done so.  Any problem is
 * reported at FATAL: in the postmaster that prevents the server from starting,
 * and in a backend it closes the connection, which is the best we can do since
 * no LIN authentication attempt could ever succeed.
 */
void
InitializeLINConfig(void)
{
	const char *tenant;
	const char *endpoint;
	const char *timeout;
	const char *cache_ttl;
	long		timeout_ms = LIN_DEFAULT_TIMEOUT_MS;
	long		ttl_seconds = LIN_DEFAULT_CACHE_TTL;

	if (lin_config_initialized)
		return;

	tenant = getenv(LIN_ENV_TENANT);
	if (tenant == NULL || tenant[0] == '\0')
		ereport(FATAL,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("environment variable \"%s\" is not set",
						LIN_ENV_TENANT),
				 errdetail("The \"lin\" authentication method requires \"%s\" to identify the tenant owning this instance.",
						   LIN_ENV_TENANT)));

	endpoint = getenv(LIN_ENV_ENDPOINT);
	if (endpoint == NULL || endpoint[0] == '\0')
		ereport(FATAL,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("environment variable \"%s\" is not set",
						LIN_ENV_ENDPOINT),
				 errdetail("The \"lin\" authentication method requires \"%s\" to locate the authentication API.",
						   LIN_ENV_ENDPOINT)));

	timeout = getenv(LIN_ENV_TIMEOUT);
	if (timeout != NULL && timeout[0] != '\0')
	{
		char	   *endptr;

		errno = 0;
		timeout_ms = strtol(timeout, &endptr, 10);

		if (errno != 0 || *endptr != '\0' || timeout_ms <= 0)
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("invalid value for environment variable \"%s\": \"%s\"",
							LIN_ENV_TIMEOUT, timeout),
					 errdetail("\"%s\" must be a positive number of milliseconds.",
							   LIN_ENV_TIMEOUT)));
	}

	cache_ttl = getenv(LIN_ENV_CACHE_TTL);
	if (cache_ttl != NULL && cache_ttl[0] != '\0')
	{
		char	   *endptr;

		errno = 0;
		ttl_seconds = strtol(cache_ttl, &endptr, 10);

		if (errno != 0 || *endptr != '\0' || ttl_seconds < 0 ||
			ttl_seconds > LIN_MAX_CACHE_TTL)
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("invalid value for environment variable \"%s\": \"%s\"",
							LIN_ENV_CACHE_TTL, cache_ttl),
					 errdetail("\"%s\" must be a number of seconds between 0 and %d, where 0 disables the cache.",
							   LIN_ENV_CACHE_TTL, LIN_MAX_CACHE_TTL)));
	}

	/*
	 * Copy the strings into a context that lives as long as the process;
	 * getenv() results are not guaranteed to stay valid.
	 */
	lin_config.tenant = MemoryContextStrdup(TopMemoryContext, tenant);
	lin_config.endpoint = MemoryContextStrdup(TopMemoryContext, endpoint);
	lin_config.timeout_ms = timeout_ms;
	lin_config.cache_ttl = (int) ttl_seconds;

	lin_config_initialized = true;

	ereport(DEBUG1,
			(errmsg_internal("LIN authentication configured for tenant \"%s\" using endpoint \"%s\" (timeout %ldms, cache %ds)",
							 lin_config.tenant, lin_config.endpoint,
							 lin_config.timeout_ms, lin_config.cache_ttl)));
}

/*
 * One-time libcurl initialization for this process.
 *
 * Deliberately not done by InitializeLINConfig(): the postmaster calls that at
 * startup, and libcurl's global state is not meant to be set up before fork().
 */
static void
lin_curl_init(void)
{
	if (lin_curl_initialized)
		return;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		ereport(FATAL,
				(errmsg("could not initialize libcurl for \"lin\" authentication")));

	lin_curl_initialized = true;
}

/*
 * libcurl write callback, accumulating the response body up to
 * LIN_MAX_RESPONSE_SIZE bytes.
 */
static size_t
lin_response_callback(char *contents, size_t size, size_t nmemb, void *userdata)
{
	LINResponse *response = (LINResponse *) userdata;
	StringInfo	buf = &response->body;
	size_t		len = size * nmemb;
	size_t		room = 0;

	if (buf->len < LIN_MAX_RESPONSE_SIZE)
		room = LIN_MAX_RESPONSE_SIZE - buf->len;

	if (len > room)
		response->truncated = true;

	if (room > 0)
		appendBinaryStringInfo(buf, contents, (int) Min(len, room));

	/*
	 * Always claim the whole chunk; returning less makes libcurl abort the
	 * transfer, and the caller decides what a truncated body means.
	 */
	return len;
}

/*
 * Build the JSON body sent to the authentication API.
 *
 * The tenant never comes from the client: it is always the value of
 * LIN_TENANT, fixed when the server (or container) was created.
 */
static void
lin_build_request_body(StringInfo body, const char *username,
					   const char *password)
{
	appendStringInfoString(body, "{\"tenant\":");
	escape_json(body, lin_config.tenant);
	appendStringInfoString(body, ",\"username\":");
	escape_json(body, username);
	appendStringInfoString(body, ",\"password\":");
	escape_json(body, password);
	appendStringInfoChar(body, '}');
}

/*
 * pg_parse_json callbacks for lin_check_response().  Between them they answer
 * two questions about the top-level object: did LIN_AUTH_FIELD say true, and
 * what does LIN_ROLE_FIELD name?
 */

/*
 * A composite value where we expected a boolean or a role name is neither, so
 * remember that the field had the wrong type.
 */
static void
lin_reject_composite(LINResponseParse *parse)
{
	switch (parse->expecting)
	{
		case LIN_FIELD_AUTHENTICATED:
			parse->auth_seen = true;
			parse->auth_bad_type = true;
			break;
		case LIN_FIELD_ROLE:
			parse->role_bad_type = true;
			break;
		case LIN_FIELD_NONE:
			break;
	}

	parse->expecting = LIN_FIELD_NONE;
}

static JsonParseErrorType
lin_object_start(void *state)
{
	LINResponseParse *parse = (LINResponseParse *) state;

	lin_reject_composite(parse);
	parse->depth++;
	return JSON_SUCCESS;
}

static JsonParseErrorType
lin_object_end(void *state)
{
	((LINResponseParse *) state)->depth--;
	return JSON_SUCCESS;
}

static JsonParseErrorType
lin_array_start(void *state)
{
	LINResponseParse *parse = (LINResponseParse *) state;

	lin_reject_composite(parse);
	parse->depth++;
	return JSON_SUCCESS;
}

static JsonParseErrorType
lin_array_end(void *state)
{
	((LINResponseParse *) state)->depth--;
	return JSON_SUCCESS;
}

static JsonParseErrorType
lin_field_start(void *state, char *fname, bool isnull)
{
	LINResponseParse *parse = (LINResponseParse *) state;

	/* Only the outermost object is interesting. */
	if (parse->depth != 1)
		return JSON_SUCCESS;

	if (strcmp(fname, LIN_AUTH_FIELD) == 0)
	{
		/*
		 * Deliberately not skipping nulls here: a null is not true, and
		 * letting it through would be reading consent into a field the service
		 * explicitly left blank.
		 */
		parse->expecting = LIN_FIELD_AUTHENTICATED;
	}
	else if (!isnull && strcmp(fname, LIN_ROLE_FIELD) == 0)
	{
		/* A null role, on the other hand, just means "no opinion". */
		parse->expecting = LIN_FIELD_ROLE;
	}

	return JSON_SUCCESS;
}

static JsonParseErrorType
lin_scalar(void *state, char *token, JsonTokenType tokentype)
{
	LINResponseParse *parse = (LINResponseParse *) state;
	LINField	expecting = parse->expecting;

	parse->expecting = LIN_FIELD_NONE;

	switch (expecting)
	{
		case LIN_FIELD_AUTHENTICATED:
			parse->auth_seen = true;

			if (tokentype == JSON_TOKEN_TRUE)
				parse->authenticated = true;
			else if (tokentype == JSON_TOKEN_FALSE)
				parse->authenticated = false;
			else
				parse->auth_bad_type = true;
			break;

		case LIN_FIELD_ROLE:
			if (tokentype == JSON_TOKEN_STRING)
				parse->role = token;
			else
				parse->role_bad_type = true;
			break;

		case LIN_FIELD_NONE:
			break;
	}

	return JSON_SUCCESS;
}

/*
 * Inspect the body of a response whose HTTP status already looked successful.
 *
 * Two things can still be learned from it.  If LIN_AUTH_FIELD is present it has
 * the last word on whether the credentials were accepted, so that a service
 * reporting a rejection with HTTP 200 is not mistaken for a success.  And
 * LIN_ROLE_FIELD, if present, names the role the connection should assume;
 * *role is set to it, or to NULL when the response says nothing, in which case
 * the client keeps the name it asked for.
 *
 * Returns STATUS_ERROR, with *logdetail set, both for an outright rejection and
 * for a response we cannot trust to answer either question: a body we could not
 * read in full, malformed JSON, or a field of the wrong type.  Failing closed
 * matters here, since the alternatives are letting the wrong person in or
 * connecting them as somebody else.
 */
static int
lin_check_response(const LINResponse *response, char **role,
				   const char **logdetail)
{
	JsonLexContext lexbuf;
	JsonLexContext *lex;
	JsonSemAction sem = {0};
	JsonParseErrorType result;
	LINResponseParse parse = {0};

	*role = NULL;

	if (response->truncated)
	{
		*logdetail = psprintf(_("The LIN authentication endpoint \"%s\" returned more than %d bytes."),
							  lin_config.endpoint, LIN_MAX_RESPONSE_SIZE);
		return STATUS_ERROR;
	}

	/*
	 * An empty body is fine: the endpoint has nothing to add, and the HTTP
	 * status already said the credentials are good.
	 */
	if (response->body.len == 0)
		return STATUS_OK;

	sem.semstate = &parse;
	sem.object_start = lin_object_start;
	sem.object_end = lin_object_end;
	sem.array_start = lin_array_start;
	sem.array_end = lin_array_end;
	sem.object_field_start = lin_field_start;
	sem.scalar = lin_scalar;

	lex = makeJsonLexContextCstringLen(&lexbuf, response->body.data,
									   response->body.len, PG_UTF8, true);
	result = pg_parse_json(lex, &sem);
	freeJsonLexContext(lex);

	if (result != JSON_SUCCESS)
	{
		*logdetail = psprintf(_("The LIN authentication endpoint \"%s\" returned a body that is not valid JSON."),
							  lin_config.endpoint);
		return STATUS_ERROR;
	}

	/* Whether the credentials were accepted comes first. */
	if (parse.auth_bad_type)
	{
		*logdetail = psprintf(_("The \"%s\" field returned by the LIN authentication endpoint \"%s\" is not a boolean."),
							  LIN_AUTH_FIELD, lin_config.endpoint);
		return STATUS_ERROR;
	}

	if (parse.auth_seen && !parse.authenticated)
	{
		*logdetail = psprintf(_("The LIN authentication endpoint \"%s\" returned \"%s\": false."),
							  lin_config.endpoint, LIN_AUTH_FIELD);
		return STATUS_ERROR;
	}

	if (parse.role_bad_type)
	{
		*logdetail = psprintf(_("The \"%s\" field returned by the LIN authentication endpoint \"%s\" is not a string."),
							  LIN_ROLE_FIELD, lin_config.endpoint);
		return STATUS_ERROR;
	}

	if (parse.role == NULL)
		return STATUS_OK;		/* no mapping requested */

	if (parse.role[0] == '\0')
	{
		*logdetail = psprintf(_("The LIN authentication endpoint \"%s\" returned an empty \"%s\" field."),
							  lin_config.endpoint, LIN_ROLE_FIELD);
		return STATUS_ERROR;
	}

	if (strlen(parse.role) >= NAMEDATALEN)
	{
		*logdetail = psprintf(_("The role \"%s\" returned by the LIN authentication endpoint \"%s\" is longer than %d bytes."),
							  parse.role, lin_config.endpoint, NAMEDATALEN - 1);
		return STATUS_ERROR;
	}

	*role = parse.role;
	return STATUS_OK;
}

/*
 * Verify one user name/password pair against the tenant's authentication API.
 *
 * Returns STATUS_OK if the API accepted the credentials, STATUS_ERROR
 * otherwise.  On failure *logdetail is set to a message for the server log;
 * it never contains the password.
 *
 * *mapped_role is set to the role the API wants this connection to assume, or
 * to NULL if it named none and the client should keep the role it asked for.
 *
 * An answer the API gave recently may be reused instead of asking again; see
 * lin_cache_lookup().  Only acceptances are cached, so a rejected credential is
 * always re-checked, and a password the user has just corrected works
 * immediately.
 */
int
lin_authenticate(const char *username, const char *password,
				 char **mapped_role, const char **logdetail)
{
	CURL	   *curl;
	CURLcode	res;
	struct curl_slist *headers = NULL;
	StringInfoData body;
	LINResponse response = {0};
	char		errbuf[CURL_ERROR_SIZE];
	long		http_code = 0;
	int			status;

	Assert(lin_config_initialized);

	*mapped_role = NULL;

	if (lin_cache_lookup(username, password, mapped_role))
	{
		ereport(DEBUG1,
				(errmsg_internal("LIN authentication served from cache for user \"%s\"",
								 username)));
		return STATUS_OK;
	}

	lin_curl_init();

	curl = curl_easy_init();
	if (curl == NULL)
		ereport(FATAL,
				(errmsg("could not create libcurl handle for \"lin\" authentication")));

	initStringInfo(&body);
	initStringInfo(&response.body);
	lin_build_request_body(&body, username, password);
	errbuf[0] = '\0';

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "Accept: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, lin_config.endpoint);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) body.len);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, lin_response_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &response);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, lin_config.timeout_ms);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, lin_config.timeout_ms);

	/* Never let libcurl use signals; we are inside a backend. */
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	/*
	 * Don't follow redirects, and refuse anything that isn't HTTP(S): either
	 * would hand the user's password to a host the administrator did not
	 * configure.  CURLOPT_PROTOCOLS is deprecated in modern Curls, but its
	 * replacement is newer than the version we require.
	 */
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
#if CURL_AT_LEAST_VERSION(7, 85, 0)
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
					 (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

	/* These are libcurl's defaults, but they are too important to imply. */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

	res = curl_easy_perform(curl);
	if (res == CURLE_OK)
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);

	/* The body holds the password, so wipe it as soon as it is unused. */
	explicit_bzero(body.data, body.len);
	pfree(body.data);

	/*
	 * A 2xx response means the credentials were accepted; anything else, up to
	 * and including not reaching the service at all, is a failure.
	 */
	if (res != CURLE_OK)
	{
		*logdetail = psprintf(_("Could not reach the LIN authentication endpoint \"%s\": %s"),
							  lin_config.endpoint,
							  errbuf[0] != '\0' ? errbuf : curl_easy_strerror(res));
		status = STATUS_ERROR;
	}
	else if (http_code >= 200 && http_code < 300)
	{
		/*
		 * The status looks like an acceptance, but the body can still overrule
		 * it, and may name a role to assume.
		 */
		status = lin_check_response(&response, mapped_role, logdetail);

		/* Only remember answers that let the user in. */
		if (status == STATUS_OK)
			lin_cache_store(username, password, *mapped_role);
	}
	else
	{
		*logdetail = psprintf(_("The LIN authentication endpoint \"%s\" rejected tenant \"%s\" user \"%s\" with HTTP status %ld: %s"),
							  lin_config.endpoint, lin_config.tenant, username,
							  http_code, response.body.data);
		status = STATUS_ERROR;
	}

	pfree(response.body.data);

	return status;
}
