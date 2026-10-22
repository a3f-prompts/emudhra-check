/* SPDX-License-Identifier: MIT */
/*
 * certstore-check - find TLS trust stores that still trust the roots of the
 * compromised eMudhra intermediates (October 2026): "emSign ECC Root CA - G3"
 * and Sectigo's cross-signing "AAA Certificate Services" (NSS label "Comodo AAA
 * Services root").  A store is PATCHED when it trusts neither for TLS servers.
 *
 * Online mode runs the installed clients (curl, openssl s_client, NSS tstclnt,
 * certutil/modutil) against test endpoints, each client gated by a control,
 * and checks files statically where no client can.  Offline mode lets rg or
 * (busybox) grep find candidate files and confirms every hit by exact DER.
 *
 * Build (C99 + POSIX.1-2008/XSI, libc only; CC = gcc, clang, musl-gcc -static,
 * aarch64-linux-gnu-gcc or arm-linux-gnueabihf-gcc):
 *   $CC -std=c99 -Wall -Wextra -Wpedantic -O2 -o certstore-check certstore-check.c
 *
 * HOW TO ADD A PROBE (or root, endpoint, bundle location, searcher)
 *  - Client/store: one probes[] entry (see struct probe) and, only if no
 *    classify_* fits, one classifier next to the others.  Placeholders in
 *    store, argv and setup: {host} {port} {url} {timeout} {bundle} {origin}
 *    {ckbi} {nssdb}.  An F_CONTROL entry, run with one embedded root as
 *    {bundle}, is the control of all F_NET entries with the same argv[0]:
 *      { "wget --ca-certificate {bundle}", PER_BUNDLE, F_NET | F_CONTROL, NULL,
 *        classify_wget, .argv = { "wget", "-q", "-O", "/dev/null", "--tries=1",
 *        "--timeout={timeout}", "--ca-directory=/nonexistent",
 *        "--ca-certificate={bundle}", "{url}" } },
 *    with classify_wget() mapping exit 0 to VULNERABLE and 5 to PATCHED.
 *  - Root: roots[] (id, CN, NSS label, PEM); patterns and controls derive from it.
 *  - Endpoint: endpoints[] (host, port, roots[] index its chain needs).
 *  - Bundle location: bundle_globs[], bundle_envs[] or a discovery_hooks[]
 *    function; libnssckbi.so: ckbi_globs[]; offline file kinds: path_classes[];
 *    searcher: searchers[] (selectable by name, self-tested before use).
 */
#define _XOPEN_SOURCE 700	/* POSIX.1-2008 with XSI (realpath, waitid) */
#define _FILE_OFFSET_BITS 64

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifdef __GNUC__			/* checks only; plain C99 compilers ignore them */
#define ATTR(x) __attribute__(x)
#else
#define ATTR(x)
#endif
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MAX_ARGV 16
#define WHY 256			/* size of every reason buffer */
#define CAPTURE_MAX (64u << 20)	/* bytes kept per child output stream */
#define CHUNK (1u << 20)	/* offline confirmation reads files in chunks... */
#define PEM_MAX (64u << 10)	/* ...overlapping by this: longest PEM block checked */

enum status { PATCHED, VULNERABLE, UNKNOWN, SKIPPED, NSTATUS };
static const char *const status_name[NSTATUS] = { "PATCHED", "VULNERABLE", "UNKNOWN", "SKIPPED" };

/* ------------------------------------------------------------------ model */

struct root {
	const char *id, *cn, *label, *pem;	/* short name, subject CN, NSS label, PEM */
	unsigned char *der;			/* the rest is derived at startup */
	size_t der_len;
	char b64[65];				/* first 64 base64 chars = 2nd PEM line */
	char *tmp_pem;				/* temp file holding only this root */
};
struct endpoint { const char *host, *port; int root; };	/* root: roots[] index */
struct item { char *path, *origin, *real; };	/* CA bundle file or libnssckbi.so */
struct itemlist { struct item *v; size_t n; };
struct target {				/* subject of one probe run; unused fields NULL */
	const struct endpoint *ep;
	const struct root *root;
	const struct item *item;
	char *nssdb;
};
struct buf { char *p; size_t len, cap; int truncated; };
struct strv { char **v; size_t n, cap; };	/* NULL-terminated, owns its strings */
struct run { int rc, timed_out; struct buf out, err; };

/* r is NULL for probes without argv (static checks) */
typedef enum status classify_fn(const struct run *r, const struct target *t, char *why);

enum iter {
	PER_ENDPOINT,	/* once per endpoint: the client's default store */
	PER_BUNDLE,	/* per CA bundle file x endpoint (F_NET) or x root */
	PER_CKBI,	/* per libnssckbi.so x root */
	CONTROL_ONLY,	/* only used as control */
};
enum {
	F_NET = 1,	/* contacts the endpoints, gated by its client's control */
	F_CONTROL = 2,	/* with one embedded root as {bundle}: control of its argv[0] */
};
struct probe {
	const char *store;			/* checklist text */
	enum iter iter;
	unsigned flags;
	const char *(*skip)(void);		/* why to skip, NULL to run */
	classify_fn *classify;			/* result -> status + reason */
	const char *argv[MAX_ARGV];		/* argv[0] from $PATH; empty: static check */
	const char *setup[2][MAX_ARGV];		/* run first, in a fresh temp dir {nssdb} */
};

struct searcher {
	const char *name;
	int recursive;			/* 1: walks directories itself, 0: we pass file lists */
	char sep;			/* separator of the file names it prints */
	const char *xdev;		/* its "stay on one filesystem" option */
	const char *argv[MAX_ARGV];	/* followed by "-e PAT"..., "--", paths */
};

static struct itemlist bundles, ckbis;

/* ------------------------------------------------------------------ tables */

static const char pem_emsign_g3[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG\n"
	"EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo\n"
	"bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g\n"
	"RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ\n"
	"TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s\n"
	"b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw\n"
	"djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0\n"
	"WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS\n"
	"fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB\n"
	"zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq\n"
	"hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB\n"
	"CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD\n"
	"+JbNR6iC8hZVdyR+EhCVBCyj\n"
	"-----END CERTIFICATE-----\n";

static const char pem_comodo_aaa[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb\n"
	"MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow\n"
	"GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj\n"
	"YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL\n"
	"MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\n"
	"BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM\n"
	"GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
	"ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua\n"
	"BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe\n"
	"3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4\n"
	"YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR\n"
	"rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm\n"
	"ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU\n"
	"oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF\n"
	"MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v\n"
	"QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t\n"
	"b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF\n"
	"AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q\n"
	"GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz\n"
	"Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2\n"
	"G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi\n"
	"l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3\n"
	"smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==\n"
	"-----END CERTIFICATE-----\n";

/* CN and label are only offline *candidate* patterns: "AAA Certificate Services"
 * is also the issuer inside many legitimate Sectigo cross-certificates, so
 * every hit is confirmed by exact DER. */
enum { ROOT_G3, ROOT_AAA };
static struct root roots[] = {
	[ROOT_G3] = { .id = "emSign-G3", .cn = "emSign ECC Root CA - G3",
		      .label = "emSign ECC Root CA - G3", .pem = pem_emsign_g3 },
	[ROOT_AAA] = { .id = "Comodo-AAA", .cn = "AAA Certificate Services",
		       .label = "Comodo AAA Services root", .pem = pem_comodo_aaa },
};
#define NROOTS ARRAY_SIZE(roots)

/* Servers whose chain validates only through one of the roots (HTTP/1.1, no h2). */
static const struct endpoint endpoints[] = {
	{ "dv-g3b-emudhra.we-have-a-problem.com", "443", ROOT_G3 },
	{ "dv-g3b-aaa-emudhra.we-have-a-problem.com", "443", ROOT_AAA },
};

/* grpc: part of gRPC C-core's system bundle list, which it tries in this order */
static const struct { const char *glob, *origin; int grpc; } bundle_globs[] = {
	{ "/etc/ssl/certs/ca-certificates.crt", "system bundle (Debian/Ubuntu/Alpine)", 1 },
	{ "/etc/pki/tls/certs/ca-bundle.crt", "system bundle (Fedora/RHEL)", 1 },
	{ "/etc/ssl/ca-bundle.pem", "system bundle (openSUSE)", 1 },
	{ "/etc/pki/tls/cacert.pem", "system bundle (OpenELEC)", 1 },
	{ "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "system bundle (RHEL ca-trust)", 1 },
	{ "/etc/ssl/cert.pem", "system bundle (Alpine/BSD style)", 0 },
	{ "/usr/share/grpc/roots.pem", "gRPC C-core bundled roots", 0 },
	{ "/usr/local/share/grpc/roots.pem", "gRPC C-core bundled roots", 0 },
	{ "/usr/lib/python3*/*-packages/certifi/cacert.pem", "certifi package file", 0 },
	{ "/usr/lib/python3*/*-packages/pip/_vendor/certifi/cacert.pem", "pip's certifi file", 0 },
	{ "/usr/lib/python3*/*-packages/grpc/_cython/_credentials/roots.pem", "grpcio roots file", 0 },
};

static const struct { const char *var, *origin; } bundle_envs[] = {
	{ "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "used by gRPC ($GRPC_DEFAULT_SSL_ROOTS_FILE_PATH)" },
	{ "SSL_CERT_FILE", "$SSL_CERT_FILE (OpenSSL)" },
	{ "CURL_CA_BUNDLE", "$CURL_CA_BUNDLE (curl)" },
	{ "REQUESTS_CA_BUNDLE", "$REQUESTS_CA_BUNDLE (python requests)" },
	{ "NODE_EXTRA_CA_CERTS", "$NODE_EXTRA_CA_CERTS (Node.js extra CAs)" },
};

static void discover_env(void), discover_grpc(void), discover_python(void);
static void (*const discovery_hooks[])(void) = { discover_env, discover_grpc, discover_python };

static const char *const ckbi_globs[] = {
	"/usr/lib64/libnssckbi.so", "/usr/lib/libnssckbi.so", "/lib64/libnssckbi.so",
	"/usr/lib/*/libnssckbi.so", "/usr/lib/*/nss/libnssckbi.so", "/usr/lib64/*/libnssckbi.so",
	"/usr/lib/nss/libnssckbi.so", "/usr/lib64/nss/libnssckbi.so", "/lib/*/libnssckbi.so",
	"/usr/local/lib/libnssckbi.so", "/opt/*/libnssckbi.so",
};

/* Searched after $PATH: some distributions keep NSS test tools here. */
#define EXTRA_TOOL_DIRS "/usr/lib64/nss/unsupported-tools:/usr/lib/nss/unsupported-tools"

/* Tried in this order; the first one that passes the self-test is used. */
static const struct searcher searchers[] = {
	/* --no-config: ignore $RIPGREP_CONFIG_PATH.  Symlinks are not followed (keep
	 * it so: absolute links in a mounted rootfs would escape to the host);
	 * --binary: search binaries, NUL ends a line; FIFOs/devices are skipped;
	 * --encoding=none: files starting with a UTF-16 BOM would be transcoded. */
	{ "rg", 1, '\0', "--one-file-system", { "rg", "--no-config", "-l", "--binary", "-F",
						"--encoding=none", "--no-ignore", "--hidden",
						"--null" } },
	/* GNU or busybox grep (busybox has no -a, and -z only with EXTRA_COMPAT).  We
	 * walk the tree ourselves: busybox grep -r blocks forever on FIFOs. */
	{ "grep", 0, '\n', NULL, { "grep", "-l", "-F" } },
};

/* Top-level directories of the live "/" that are never searched. */
static const char *const live_skip[] = { "proc", "sys", "dev", "run", ".snapshots" };

#define SOURCE_FILE "CA source file, trusted only via a bundle built from it"

/* Offline hits in these files do not mean "trusted" (first match wins).  base:
 * match a file name prefix, else a path substring; feed: judged online in --all. */
static const struct path_class {
	const char *match;
	int base;
	enum status st;
	const char *why;
	struct itemlist *feed;
} path_classes[] = {
	{ "libnssckbi", 1, UNKNOWN, "NSS builtins, keeps distrusted roots (see NSS probes)", &ckbis },
	{ "cert9.db", 1, UNKNOWN, "NSS db, may distrust it (certutil -L -d sql:DIR)", NULL },
	{ "cert8.db", 1, UNKNOWN, "NSS db, may distrust it (certutil -L -d DIR)", NULL },
	{ "/blocklist/", 0, PATCHED, "distrust (blocklist) entry", NULL },
	{ "/blacklist/", 0, PATCHED, "distrust (blacklist) entry", NULL },
	{ "/share/ca-certificates/", 0, SKIPPED, SOURCE_FILE, NULL },
	{ "/ca-trust/source/", 0, SKIPPED, SOURCE_FILE, NULL },
	{ "/ca-trust-source/", 0, SKIPPED, SOURCE_FILE, NULL },
};

/* ------------------------------------------------------------------ utilities */

static int opt_verbose, opt_xdev, opt_timeout = 15;
static const char *opt_searcher;
static char *g_tmpdir;
static struct stat g_self;		/* our executable, ignored by the offline search */
static volatile sig_atomic_t g_stop, g_child;

/* SGR sequences, written only to a stream with colors on (see set_color()). */
enum color { RESET, BOLD, GREY, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, NCOLOR };
static const char *const sgr[NCOLOR] = {
	"\033[0m", "\033[1m", "\033[90m", "\033[1;31m", "\033[32m", "\033[33m", "\033[1;34m",
	"\033[35m", "\033[36m",
};
static const enum color status_color[NSTATUS] = { GREEN, RED, YELLOW, CYAN };
static int g_color[3];				/* by fd: 1 stdout, 2 stderr */
#define C(c) (g_color[1] ? sgr[c] : "")		/* for stdout */
#define E(c) (g_color[2] ? sgr[c] : "")		/* for stderr */

/* --color=WHEN: always, never or auto: on a terminal, unless $NO_COLOR is set
 * and not empty (no-color.org) or TERM=dumb. */
static int set_color(const char *when)
{
	const char *nc = getenv("NO_COLOR"), *term = getenv("TERM");
	int always = !strcmp(when, "always"), autom = !strcmp(when, "auto");

	if (!always && !autom && strcmp(when, "never"))
		return -1;
	for (int fd = 1; fd <= 2; fd++)
		g_color[fd] = always || (autom && isatty(fd) && !(nc && *nc) &&
					 !(term && !strcmp(term, "dumb")));
	return 0;
}

static ATTR((noreturn, format(printf, 1, 2))) void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%scertstore-check:%s ", E(RED), E(RESET));
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(3);
}

static void *xrealloc(void *p, size_t n)
{
	if (!(p = realloc(p, n ? n : 1)))
		die("out of memory");
	return p;
}
#define xmalloc(n) xrealloc(NULL, (n))

static ATTR((format(printf, 1, 2))) char *xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *s;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0)
		die("vsnprintf failed");
	s = xmalloc((size_t)n + 1);
	va_start(ap, fmt);
	vsnprintf(s, (size_t)n + 1, fmt, ap);
	va_end(ap);
	return s;
}
#define xstrdup(s) xasprintf("%s", (s))

static void buf_add(struct buf *b, const void *d, size_t n)
{
	if (b->len + n + 1 > b->cap)
		b->p = xrealloc(b->p, b->cap = (b->len + n + 1) * 2);
	memcpy(b->p + b->len, d, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static const char *buf_str(const struct buf *b) { return b->p ? b->p : ""; }

static void strv_add(struct strv *s, char *str)	/* takes ownership */
{
	if (s->n + 2 > s->cap)
		s->v = xrealloc(s->v, (s->cap = s->cap ? 2 * s->cap : 16) * sizeof(*s->v));
	s->v[s->n++] = str;
	s->v[s->n] = NULL;
}

static void strv_free(struct strv *s)
{
	for (size_t i = 0; i < s->n; i++)
		free(s->v[i]);
	free(s->v);
	memset(s, 0, sizeof(*s));
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Portable memmem(). */
static const unsigned char *mem_find(const void *hay, size_t hl, const void *needle, size_t nl)
{
	const unsigned char *p = hay, *n = needle, *last;

	if (nl == 0 || hl < nl)
		return NULL;
	for (last = p + (hl - nl); p <= last && (p = memchr(p, n[0], (size_t)(last - p) + 1)); p++)
		if (memcmp(p, n, nl) == 0)
			return p;
	return NULL;
}

/* Cut trailing characters of s that are in set. */
static char *rtrim(char *s, const char *set)
{
	for (size_t n = strlen(s); n && strchr(set, s[n - 1]);)
		s[--n] = '\0';
	return s;
}

static int is_regular(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Full path of an executable in $PATH or EXTRA_TOOL_DIRS, NULL if absent. */
static char *find_tool(const char *name)
{
	const char *path = getenv("PATH");
	char *dirs, *dir, *save = NULL, *found = NULL;

	if (strchr(name, '/'))
		return access(name, X_OK) ? NULL : xstrdup(name);
	dirs = xasprintf("%s:%s", path ? path : "/usr/bin:/bin", EXTRA_TOOL_DIRS);
	for (dir = strtok_r(dirs, ":", &save); dir && !found; dir = strtok_r(NULL, ":", &save)) {
		found = xasprintf("%s/%s", dir, name);
		if (!is_regular(found) || access(found, X_OK)) {
			free(found);
			found = NULL;
		}
	}
	free(dirs);
	return found;
}

static int tool_exists(const char *name)
{
	char *p = find_tool(name);
	int found = p != NULL;

	free(p);
	return found;
}

/* Append to a list, deduplicated by realpath; origins of duplicates are merged. */
static void item_add(struct itemlist *l, const char *path, const char *origin)
{
	char real[PATH_MAX], cwd[PATH_MAX], *abs, *o;
	size_t i;

	abs = path[0] == '/' ? xstrdup(path) :
	      xasprintf("%s/%s", getcwd(cwd, sizeof(cwd)) ? cwd : ".", path);
	if (!realpath(abs, real))
		snprintf(real, sizeof(real), "%s", abs);
	for (i = 0; i < l->n && strcmp(l->v[i].real, real); i++)
		;
	if (i == l->n) {
		l->v = xrealloc(l->v, (l->n + 1) * sizeof(*l->v));
		l->v[l->n++] = (struct item){ abs, xstrdup(origin), xstrdup(real) };
		return;
	}
	if (!strstr(l->v[i].origin, origin)) {
		o = xasprintf("%s, %s", l->v[i].origin, origin);
		free(l->v[i].origin);
		l->v[i].origin = o;
	}
	free(abs);
}

static void add_glob(struct itemlist *l, const char *pattern, const char *origin)
{
	glob_t g;

	memset(&g, 0, sizeof(g));
	if (glob(pattern, 0, NULL, &g) == 0)
		for (size_t i = 0; i < g.gl_pathc; i++)
			if (is_regular(g.gl_pathv[i]))
				item_add(l, g.gl_pathv[i], origin);
	globfree(&g);
}

static void rm_tree(const char *path)
{
	struct stat st;
	struct dirent *e;
	DIR *d;

	if (lstat(path, &st))
		return;
	if (!S_ISDIR(st.st_mode) || !(d = opendir(path))) {
		unlink(path);
		return;
	}
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
			char *sub = xasprintf("%s/%s", path, e->d_name);

			rm_tree(sub);
			free(sub);
		}
	}
	closedir(d);
	rmdir(path);
}

/* g_tmpdir: new absolute temp dir (children run in "/"), removed by cleanup(). */
static void make_tmpdir(void)
{
	const char *tmp = getenv("TMPDIR");
	char *dir = xasprintf("%s/certstore-check.XXXXXX", tmp && *tmp ? tmp : "/tmp");

	if (!mkdtemp(dir))
		die("mkdtemp %s: %s", dir, strerror(errno));
	if (!(g_tmpdir = realpath(dir, NULL))) {
		rmdir(dir);
		die("realpath %s: %s", dir, strerror(errno));
	}
	free(dir);
}

static char *write_tmp(const char *name, const void *data, size_t len)
{
	char *path = xasprintf("%s/%s", g_tmpdir, name);
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);

	if (fd < 0 || write(fd, data, len) != (ssize_t)len || close(fd))
		die("cannot write %s: %s", path, strerror(errno));
	return path;
}

/* ------------------------------------------------------------------ base64 / PEM / DER */

static int b64_value(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	return c == '+' ? 62 : c == '/' ? 63 : -1;
}

/* Decode base64 in [s, e) into out (room for e - s bytes).  Blanks, quotes and
 * \n \r \t escapes are skipped (and flagged in *escaped) so PEM pasted into C
 * sources or JSON decodes too.  Returns the length, or -1 on other characters. */
static long b64_decode(const unsigned char *s, const unsigned char *e, unsigned char *out,
		       int *escaped)
{
	unsigned acc = 0;
	int bits = 0, v;
	long n = 0;

	for (*escaped = 0; s < e && *s != '='; s++) {
		if (*s == '\\' && s + 1 < e && (s[1] == 'n' || s[1] == 'r' || s[1] == 't')) {
			s++;
			*escaped = 1;
			continue;
		}
		*escaped |= *s == '"';
		if (strchr(" \t\r\n\"", *s))
			continue;
		if ((v = b64_value(*s)) < 0)
			return -1;
		acc = ((acc << 6) | (unsigned)v) & 0xffffu;
		if ((bits += 6) >= 8)
			out[n++] = (unsigned char)(acc >> (bits -= 8));
	}
	return n;
}

/* Read a DER tag and length at *p, leave *p at the value; -1 if malformed. */
static int der_tlv(const unsigned char **p, const unsigned char *e, size_t *len)
{
	size_t n = 0, k;
	int tag;

	if (e - *p < 2)
		return -1;
	tag = *(*p)++;
	if ((k = *(*p)++) & 0x80) {
		if ((k &= 0x7f) == 0 || k > sizeof(size_t) || (size_t)(e - *p) < k)
			return -1;
		while (k--)
			n = n << 8 | *(*p)++;
	} else {
		n = k;
	}
	*len = n;
	return n > (size_t)(e - *p) ? -1 : tag;
}

/* OpenSSL "TRUSTED CERTIFICATE" aux data (after the DER) judged like OpenSSL's
 * obj_trust() for TLS servers: serverAuth or anyEKU rejected -> 0; a trust list
 * -> 1 only if it has one of them; no lists -> 1 (plain trust anchor). */
static int aux_trusts_tls(const unsigned char *p, const unsigned char *e)
{
	static const unsigned char server_auth[] = { 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 1 };
	static const unsigned char any_eku[] = { 6, 4, 0x55, 0x1d, 0x25, 0 };
	int tag, has_trust = 0, trusted = 0;
	size_t len;

	if (der_tlv(&p, e, &len) != 0x30)
		return 1;
	for (e = p + len; p < e && (tag = der_tlv(&p, e, &len)) >= 0; p += len) {
		int listed = mem_find(p, len, server_auth, sizeof(server_auth)) ||
			     mem_find(p, len, any_eku, sizeof(any_eku));

		if (tag == 0xa0 && listed)	/* [0] reject list */
			return 0;
		if (tag == 0x30)		/* trust list */
			has_trust = 1, trusted = listed;
	}
	return has_trust ? trusted : 1;
}

static void init_roots(void)
{
	for (struct root *r = roots; r < roots + NROOTS; r++) {
		const char *body = strchr(r->pem, '\n'), *end = strstr(r->pem, "-----END");
		size_t k = 0;
		long n = -1;
		int esc;

		if (body && end && end > body) {
			r->der = xmalloc((size_t)(end - body));
			n = b64_decode((const unsigned char *)body, (const unsigned char *)end,
				       r->der, &esc);
		}
		if (n < 64)
			die("embedded PEM of %s is malformed", r->id);
		r->der_len = (size_t)n;
		for (; body < end && k < 64; body++)
			if (b64_value((unsigned char)*body) >= 0)
				r->b64[k++] = *body;
	}
}

/* PEM_ESC: PEM with \n escapes or quotes (source code, JSON); NOT_TLS: OpenSSL
 * TRUSTED CERTIFICATE whose aux trust excludes TLS server authentication */
enum { HIT_DER = 1, HIT_PEM = 2, HIT_PEM_ESC = 4, HIT_NOT_TLS = 8 };

/* Decode one PEM block, labelled [label, label + llen), and compare it with the roots. */
static void check_pem(const unsigned char *label, size_t llen, const unsigned char *body,
		      const unsigned char *end, unsigned *hits)
{
	static unsigned char der[PEM_MAX];
	int trusted = llen == 19 && !memcmp(label, "TRUSTED CERTIFICATE", 19), esc;
	long len;

	if ((!trusted && (llen != 11 || memcmp(label, "CERTIFICATE", 11))) ||
	    (size_t)(end - body) > PEM_MAX || (len = b64_decode(body, end, der, &esc)) < 0)
		return;
	for (size_t i = 0; i < NROOTS; i++) {
		const struct root *r = &roots[i];

		if ((size_t)len < r->der_len || memcmp(der, r->der, r->der_len))
			continue;
		if (trusted && !aux_trusts_tls(der + r->der_len, der + len))
			hits[i] |= HIT_NOT_TLS;
		else if (trusted || (size_t)len == r->der_len)
			hits[i] |= esc ? HIT_PEM_ESC : HIT_PEM;
	}
}

/* Check the "-----BEGIN X-----...-----END" blocks in [p, e) in one linear pass:
 * the END found is reused for the BEGINs before it, and a block that contains
 * another BEGIN is skipped up to that one. */
static void scan_pem(const unsigned char *p, const unsigned char *e, unsigned *hits)
{
	const unsigned char *beg, *lend, *end = NULL, *next;

	while ((beg = mem_find(p, (size_t)(e - p), "-----BEGIN ", 11)) != NULL) {
		p = beg + 11;
		if ((!end || end < p) && !(end = mem_find(p, (size_t)(e - p), "-----END ", 9)))
			return;
		if (!(lend = mem_find(p, end - p < 80 ? (size_t)(end - p) : 80, "-----", 5)))
			continue;
		if ((next = mem_find(lend + 5, (size_t)(end - lend - 5), "-----BEGIN ", 11))) {
			p = next;
			continue;
		}
		check_pem(p, (size_t)(lend - p), lend + 5, end, hits);
		p = end + 9;
	}
}

static ssize_t read_full(int fd, unsigned char *p, size_t len)
{
	size_t n = 0;
	ssize_t got;

	while (n < len && !g_stop && (got = read(fd, p + n, len - n)) != 0) {
		if (got < 0 && errno != EINTR)
			return -1;
		n += got > 0 ? (size_t)got : 0;
	}
	return (ssize_t)n;
}

/* Confirm a candidate: exact DER bytes, or decoded PEM blocks equal to the DER.
 * Read in chunks overlapping by PEM_MAX, so every DER copy or PEM block is seen
 * whole once (no mmap: a file shrinking under us must not raise SIGBUS). */
static int confirm_file(const char *path, unsigned *hits, int *binary)
{
	static unsigned char *buf;
	int fd = open(path, O_RDONLY | O_NOCTTY | O_NONBLOCK), err = 0;
	size_t keep = 0, n;
	struct stat st;
	ssize_t got;

	if (fd < 0)
		return -1;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
	    (st.st_dev == g_self.st_dev && st.st_ino == g_self.st_ino)) {
		close(fd);
		return 0;
	}
	if (!buf)
		buf = xmalloc(PEM_MAX + CHUNK);
	do {
		if ((got = read_full(fd, buf + keep, CHUNK)) < 0) {
			err = errno;
			break;
		}
		n = keep + (size_t)got;
		if (!keep)
			*binary = memchr(buf, 0, n < 4096 ? n : 4096) != NULL;
		for (size_t i = 0; i < NROOTS; i++)
			if (mem_find(buf, n, roots[i].der, roots[i].der_len))
				hits[i] |= HIT_DER;
		scan_pem(buf, buf + n, hits);
		keep = n < PEM_MAX ? n : PEM_MAX;
		memmove(buf, buf + n - keep, keep);
	} while ((size_t)got == CHUNK && !g_stop);
	close(fd);
	errno = err;
	return err ? -1 : 0;
}

/* ------------------------------------------------------------------ child processes */

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
	if (g_child > 0)
		kill(-(pid_t)g_child, SIGKILL);
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

/* Collect a child's stdout/stderr until both close, the deadline passes or we stop. */
static void pump(int ofd, int efd, long long deadline, struct run *r)
{
	struct pollfd pfd[2] = { { ofd, POLLIN, 0 }, { efd, POLLIN, 0 } };
	char chunk[16384];

	while ((pfd[0].fd >= 0 || pfd[1].fd >= 0) && !g_stop) {
		long long left = deadline ? deadline - now_ms() : -1;
		int n;

		if (deadline && left <= 0) {
			r->timed_out = 1;
			return;
		}
		n = poll(pfd, 2, left < 0 ? -1 : left > INT_MAX ? INT_MAX : (int)left);
		if (n < 0 && errno != EINTR)
			return;
		for (int i = 0; n > 0 && i < 2; i++) {
			struct buf *b = i ? &r->err : &r->out;
			ssize_t got;

			if (pfd[i].fd < 0 || !pfd[i].revents)
				continue;
			got = read(pfd[i].fd, chunk, sizeof(chunk));
			if (got == 0 || (got < 0 && errno != EINTR))
				pfd[i].fd = -1;
			else if (got > 0 && b->len + (size_t)got > CAPTURE_MAX)
				b->truncated = 1;
			else if (got > 0)
				buf_add(b, chunk, (size_t)got);
		}
	}
}

/* In the child: stdin from /dev/null, stdout/stderr to the pipes, cwd "/". */
static void child_exec(char *const argv[], int out, int err)
{
	int null = open("/dev/null", O_RDONLY);

	setpgid(0, 0);
	signal(SIGPIPE, SIG_DFL);
	if (null < 0 || dup2(null, 0) < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0)
		_exit(127);
	close(null);	/* all > 2: main() keeps fds 0-2 open */
	close(out);
	close(err);
	if (chdir("/") == 0)
		execvp(argv[0], argv);
	dprintf(2, "exec %s: %s\n", argv[0], strerror(errno));
	_exit(127);
}

/* Run argv with stdin from /dev/null, capture its output, kill its whole process
 * group after timeout seconds (0 = no limit) or on a signal, always reap it. */
static void run_cmd(char *const argv[], int timeout, struct run *r)
{
	long long deadline = timeout > 0 ? now_ms() + timeout * 1000LL : 0;
	int o[2], e[2], st = 0;
	siginfo_t si;
	pid_t pid;

	memset(r, 0, sizeof(*r));
	if (pipe(o) || pipe(e))
		die("pipe: %s", strerror(errno));
	fcntl(o[0], F_SETFD, FD_CLOEXEC);
	fcntl(e[0], F_SETFD, FD_CLOEXEC);
	fflush(NULL);
	if ((pid = fork()) < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0)
		child_exec(argv, o[1], e[1]);
	setpgid(pid, pid);
	g_child = (sig_atomic_t)pid;
	close(o[1]);
	close(e[1]);
	pump(o[0], e[0], deadline, r);
	/* The child may outlive its output: same deadline, wait without reaping. */
	while (!g_stop && !r->timed_out) {
		memset(&si, 0, sizeof(si));
		if (waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) < 0 ?
		    errno != EINTR : si.si_pid == pid)
			break;
		if (deadline && now_ms() >= deadline)
			r->timed_out = 1;
		else
			poll(NULL, 0, 10);
	}
	kill(-pid, SIGKILL);	/* the child on timeout/stop, else what is left of its group */
	while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
		;
	g_child = 0;
	close(o[0]);
	close(e[0]);
	r->rc = WIFEXITED(st) ? WEXITSTATUS(st) : WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1;
}

static void run_free(struct run *r)
{
	free(r->out.p);
	free(r->err.p);
	memset(r, 0, sizeof(*r));
}

/* First line of b containing needle, else its last non-empty line. */
static const char *pick_line(const struct buf *b, const char *needle)
{
	static char line[160];
	const char *p = buf_str(b), *best = NULL;
	size_t len = 0;

	for (; *p; p += len + (p[len] == '\n')) {
		if (!(len = strcspn(p, "\n")))
			continue;
		best = p;
		if (needle && mem_find(p, len, needle, strlen(needle)))
			break;
	}
	if (!best)
		return "(no message)";
	snprintf(line, sizeof(line), "%.*s", (int)strcspn(best, "\n"), best);
	return rtrim(line, "\r ");
}

/* -v: argv shell-quoted, the first nshow entries plus a count of nmore paths. */
static void print_argv(char *const argv[], size_t nshow, size_t nmore)
{
	printf("%s    $", C(GREY));
	for (size_t i = 0; argv[i] && i < nshow; i++) {
		int q = !*argv[i] || strpbrk(argv[i], " \t\n'\"\\$*?[]{}()<>|&;`~#");

		fputs(q ? " '" : " ", stdout);
		for (const char *c = argv[i]; *c; c++) {
			if (*c == '\'')
				fputs("'\\''", stdout);
			else
				putchar(*c);
		}
		if (q)
			putchar('\'');
	}
	if (nmore)
		printf(" <%zu paths>", nmore);
	printf("%s\n", C(RESET));
}

/* -v: the last `lines` non-empty lines of b. */
static void print_tail(const struct buf *b, int lines)
{
	const char *s = buf_str(b), *end = s + strlen(s), *p;

	for (p = end; p > s && lines; p--)
		if (p[-1] != '\n' && (p - 1 == s || p[-2] == '\n'))
			lines--;
	for (size_t l; p < end; p += l + 1)
		if ((l = strcspn(p, "\n")))
			printf("%s    | %.*s%s\n", C(GREY), (int)(l > 200 ? 200 : l), p, C(RESET));
}

/* ------------------------------------------------------------------ reporting */

static struct strv vulnerable;		/* stores with a VULNERABLE line */
static unsigned counts[NSTATUS];

/* Copy with control characters replaced: one output line per check or file. */
static char *printable(const char *s)
{
	char *p = xstrdup(s);

	for (char *c = p; *c; c++)
		if ((unsigned char)*c < 0x20 || *c == 0x7f)
			*c = '?';
	return p;
}

/* One checklist line: status, store, root (@ endpoint), reason. */
static ATTR((format(printf, 5, 6))) void report(enum status st, const char *store,
		const struct root *r, const struct endpoint *ep, const char *fmt, ...)
{
	char why[WHY], *name = printable(store);
	va_list ap;
	size_t i;

	va_start(ap, fmt);
	vsnprintf(why, sizeof(why), fmt, ap);
	va_end(ap);
	printf("%s[%s]%s%*s %s%s%s | %s%s%s", C(status_color[st]), status_name[st], C(RESET),
	       10 - (int)strlen(status_name[st]), "", C(BOLD), name, C(RESET),
	       r ? C(MAGENTA) : "", r ? r->id : "-", r ? C(RESET) : "");
	if (ep)		/* first DNS label; the full names are listed once above */
		printf(" @ %.*s", (int)strcspn(ep->host, "."), ep->host);
	printf(" | %s\n", why);
	fflush(stdout);
	counts[st]++;
	for (i = 0; st == VULNERABLE && i < vulnerable.n && strcmp(vulnerable.v[i], name); i++)
		;
	if (st == VULNERABLE && i == vulnerable.n)	/* list every store once */
		strv_add(&vulnerable, name);
	else
		free(name);
}

static int summary(void)
{
	static const enum status order[] = { VULNERABLE, UNKNOWN, PATCHED, SKIPPED };

	printf("\n%sSummary:%s", C(BOLD), C(RESET));
	for (size_t i = 0; i < ARRAY_SIZE(order); i++) {
		unsigned n = counts[order[i]];

		printf("%s %s%u %s%s", i ? "," : "", n ? C(status_color[order[i]]) : "", n,
		       status_name[order[i]], n ? C(RESET) : "");
	}
	putchar('\n');
	if (counts[VULNERABLE])
		printf("%sNot patched (still trusting a compromised root):%s\n", C(RED), C(RESET));
	for (size_t i = 0; i < vulnerable.n; i++)
		printf("  %s%s%s\n", C(BOLD), vulnerable.v[i], C(RESET));
	if (counts[UNKNOWN])
		printf("%sUNKNOWN checks could not be decided; rerun with -v for commands and "
		       "messages.%s\n", C(YELLOW), C(RESET));
	return counts[VULNERABLE] ? 1 : counts[UNKNOWN] ? 2 : 0;
}

/* ------------------------------------------------------------------ classifiers */

static ATTR((format(printf, 3, 4))) enum status verdict(enum status st, char *why,
							 const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(why, WHY, fmt, ap);
	va_end(ap);
	return st;
}

static enum status classify_curl(const struct run *r, const struct target *t, char *why)
{
	(void)t;
	if (r->rc == 0)
		return verdict(VULNERABLE, why, "chain accepted (curl exit 0)");
	if (r->rc == 60)
		return verdict(PATCHED, why, "certificate verification failed (curl exit 60)");
	return verdict(UNKNOWN, why, "curl exit %d: %s", r->rc, pick_line(&r->err, "curl: ("));
}

static enum status classify_openssl(const struct run *r, const struct target *t, char *why)
{
	const char *v = strstr(buf_str(&r->err), "verify error:num=");
	int num;

	(void)t;
	if (r->rc == 0 && !v)
		return verdict(VULNERABLE, why, "chain verified (openssl exit 0)");
	if (!v)
		return verdict(UNKNOWN, why, "openssl exit %d: %s", r->rc, pick_line(&r->err, "error"));
	num = atoi(v + 17);
	/* 2/20: issuer not found, 19: untrusted root in chain, 21: leaf unverifiable */
	return verdict(num == 2 || num == 19 || num == 20 || num == 21 ? PATCHED : UNKNOWN, why,
		       "openssl verify error %d", num);
}

static enum status classify_tstclnt(const struct run *r, const struct target *t, char *why)
{
	static const char *const rejects[] = {
		"SEC_ERROR_UNTRUSTED_CERT", "SEC_ERROR_UNKNOWN_ISSUER", "SEC_ERROR_UNTRUSTED_ISSUER",
	};

	(void)t;
	if (r->rc == 0)
		return verdict(VULNERABLE, why, "handshake accepted (tstclnt exit 0)");
	for (size_t i = 0; i < ARRAY_SIZE(rejects); i++)
		if (strstr(buf_str(&r->err), rejects[i]) || strstr(buf_str(&r->out), rejects[i]))
			return verdict(PATCHED, why, "rejected: %s (tstclnt exit %d)", rejects[i], r->rc);
	return verdict(UNKNOWN, why, "tstclnt exit %d: %s", r->rc, pick_line(&r->err, "tstclnt:"));
}

/* certutil -L lines: "<token>:<label>   <SSL>,<S/MIME>,<code>".  'C' in the SSL
 * field = trusted for TLS servers; "p" alone = explicitly distrusted. */
static enum status classify_certutil(const struct run *r, const struct target *t, char *why)
{
	const char *p = buf_str(&r->out);
	char flags[64] = "";
	int listed = 0, found = 0, trusted = 0;

	if (r->rc != 0)
		return verdict(UNKNOWN, why, "certutil -L exit %d: %s", r->rc, pick_line(&r->err, NULL));
	for (size_t len; *p; p += len + (p[len] == '\n')) {
		char line[512], *sp, *name;

		len = strcspn(p, "\n");
		snprintf(line, sizeof(line), "%.*s", (int)len, p);
		if (!(sp = strrchr(rtrim(line, " \r"), ' ')) || !strchr(sp + 1, ','))
			continue;	/* header lines */
		*sp = '\0';
		name = strchr(rtrim(line, " "), ':') ? strchr(line, ':') + 1 : line;
		listed += name != line;
		if (strcmp(name, t->root->label) && strcmp(name, t->root->cn))
			continue;
		if (!trusted)	/* show the flags of a trusted entry if there is one */
			snprintf(flags, sizeof(flags), "%s", sp + 1);
		found = 1;
		trusted |= memchr(sp + 1, 'C', strcspn(sp + 1, ",")) != NULL;
	}
	if (!listed)
		return verdict(UNKNOWN, why, "module listed no certificates (failed to load?)");
	if (!found)
		return verdict(PATCHED, why, "\"%s\" not in module (removed)", t->root->label);
	return verdict(trusted ? VULNERABLE : PATCHED, why, "\"%s\" %s (trust flags %s)",
		       t->root->label, trusted ? "trusted for TLS" : "present, not trusted for TLS",
		       flags);
}

/* Static check of a CA bundle or libnssckbi.so (an item of ckbis) without any
 * client: which roots the file contains. */
static enum status classify_static(const struct run *r, const struct target *t, char *why)
{
	unsigned hits[NROOTS] = { 0 }, h;
	int binary, ckbi = 0;

	(void)r;
	for (size_t i = 0; i < ckbis.n; i++)
		ckbi |= t->item == &ckbis.v[i];
	if (confirm_file(t->item->path, hits, &binary))
		return verdict(UNKNOWN, why, "unreadable: %s", strerror(errno));
	h = hits[t->root - roots];
	if (ckbi)
		return h & HIT_DER ? verdict(UNKNOWN, why, "module contains %s; trust flags unknown "
					     "without certutil", t->root->cn) :
		       verdict(PATCHED, why, "%s not in module (removed)", t->root->cn);
	if (h & (HIT_PEM | HIT_DER))
		return verdict(VULNERABLE, why, "contains %s (static check)", t->root->cn);
	return verdict(PATCHED, why, "%s (static check)", h & HIT_NOT_TLS ?
		       "entry excludes TLS server auth" : "root not in file");
}

static int client_ok(const char *tool);	/* its control passed for every endpoint */

static const char *skip_if_curl_works(void)
{
	return client_ok("curl") ? "fallback only, curl works" : NULL;
}

static const char *skip_if_client_works(void)
{
	return client_ok("curl") ? "checked with curl" :
	       client_ok("openssl") ? "checked with openssl" : NULL;
}

static const char *skip_if_certutil(void)
{
	return tool_exists("certutil") && tool_exists("modutil") ? "checked with certutil" : NULL;
}

static const char *skip_unless_ckbi(void)
{
	return ckbis.n ? NULL : "no libnssckbi.so found, -b would load no roots";
}

static const char *skip_unless_pki_nssdb(void)
{
	struct stat st;

	return stat("/etc/pki/nssdb", &st) == 0 && S_ISDIR(st.st_mode) ? NULL : "no /etc/pki/nssdb";
}

/* ------------------------------------------------------------------ probes */

/* -q (first!): ignore ~/.curlrc, which could e.g. say "insecure" */
#define CURL "curl", "-q", "-sS", "-o", "/dev/null", "--max-time", "{timeout}"
#define S_CLIENT "openssl", "s_client", "-connect", "{host}:{port}", "-servername", "{host}", \
		 "-verify_return_error"
#define TSTCLNT "tstclnt", "-h", "{host}", "-p", "{port}", "-Q"
#define NSS_NEWDB { "certutil", "-N", "-d", "sql:{nssdb}", "--empty-password" }

static const struct probe probes[] = {
	{ "curl, default CA store", PER_ENDPOINT, F_NET, NULL, classify_curl,
	  .argv = { CURL, "{url}" } },
	{ "curl --cacert {bundle}", PER_BUNDLE, F_NET | F_CONTROL, NULL, classify_curl,
	  .argv = { CURL, "--cacert", "{bundle}", "--capath", "/dev/null", "{url}" } },
	{ "openssl s_client, default CA store", PER_ENDPOINT, F_NET, skip_if_curl_works,
	  classify_openssl, .argv = { S_CLIENT } },
	{ "openssl s_client -CAfile {bundle}", PER_BUNDLE, F_NET | F_CONTROL, skip_if_curl_works,
	  classify_openssl, .argv = { S_CLIENT, "-CAfile", "{bundle}", "-no-CApath" } },
	{ "CA bundle {bundle}", PER_BUNDLE, 0, skip_if_client_works, classify_static,
	  .argv = { NULL } },
	{ "NSS temp db trusting only {bundle}", CONTROL_ONLY, F_NET | F_CONTROL, NULL,
	  classify_tstclnt, .argv = { TSTCLNT, "-d", "sql:{nssdb}" },
	  .setup = { NSS_NEWDB, { "certutil", "-A", "-d", "sql:{nssdb}", "-n", "control",
				  "-t", "C,,", "-i", "{bundle}" } } },
	{ "NSS builtins (tstclnt -D -b)", PER_ENDPOINT, F_NET, skip_unless_ckbi, classify_tstclnt,
	  .argv = { TSTCLNT, "-D", "-b" } },
	{ "NSS system db /etc/pki/nssdb + builtins (tstclnt -b)", PER_ENDPOINT, F_NET,
	  skip_unless_pki_nssdb, classify_tstclnt,
	  .argv = { TSTCLNT, "-d", "sql:/etc/pki/nssdb", "-b" } },
	{ "NSS builtins {ckbi} (certutil)", PER_CKBI, 0, NULL, classify_certutil,
	  .argv = { "certutil", "-L", "-d", "sql:{nssdb}", "-h", "all" },
	  .setup = { NSS_NEWDB, { "modutil", "-dbdir", "sql:{nssdb}", "-add", "Builtin Roots",
				  "-libfile", "{ckbi}", "-force" } } },
	{ "NSS builtins {ckbi} (static)", PER_CKBI, 0, skip_if_certutil, classify_static,
	  .argv = { NULL } },
};

/* ------------------------------------------------------------------ online engine */

enum { CTRL_UNSET, CTRL_OK, CTRL_FAILED, CTRL_NONE };
static struct ctl { int state; char why[WHY]; } ctls[ARRAY_SIZE(probes)][ARRAY_SIZE(endpoints)];

/* Substitute {placeholders}; unset ones (SKIPPED lines) become <name>. */
static char *expand(const char *s, const struct target *t)
{
	const struct endpoint *ep = t->ep;
	const struct item *it = t->item;
	char url[WHY], timeout[16], unset[16];
	const char *const vars[][2] = {
		{ "{host}", ep ? ep->host : NULL }, { "{port}", ep ? ep->port : NULL },
		{ "{url}", ep ? url : NULL }, { "{timeout}", timeout },
		{ "{bundle}", it ? it->path : NULL }, { "{ckbi}", it ? it->path : NULL },
		{ "{origin}", it ? it->origin : NULL }, { "{nssdb}", t->nssdb },
	};
	struct buf b = { 0 };

	if (ep)
		snprintf(url, sizeof(url), "https://%s:%s/", ep->host, ep->port);
	snprintf(timeout, sizeof(timeout), "%d", opt_timeout);
	for (buf_add(&b, "", 0); *s;) {
		size_t i, k = 0;
		const char *v;

		for (i = 0; i < ARRAY_SIZE(vars); i++)
			if (!strncmp(s, vars[i][0], k = strlen(vars[i][0])))
				break;
		if (i == ARRAY_SIZE(vars)) {
			buf_add(&b, s++, 1);
			continue;
		}
		if (!(v = vars[i][1])) {
			snprintf(unset, sizeof(unset), "<%.*s>", (int)k - 2, vars[i][0] + 1);
			v = unset;
		}
		buf_add(&b, v, strlen(v));
		s += k;
	}
	return b.p;
}

static void run_template(const char *const tmpl[], const struct target *t, struct run *r)
{
	char *argv[MAX_ARGV + 1];
	size_t i;

	for (i = 0; i < MAX_ARGV && tmpl[i]; i++)
		argv[i] = i ? expand(tmpl[i], t) : find_tool(tmpl[0]);
	argv[i] = NULL;
	if (!argv[0])
		argv[0] = xstrdup(tmpl[0]);
	if (opt_verbose)
		print_argv(argv, i, 0);
	run_cmd(argv, opt_timeout + 1, r);
	if (opt_verbose) {
		printf("%s    exit %d%s%s\n", C(GREY), r->rc, r->timed_out ? " (timed out, killed)" : "",
		       C(RESET));
		print_tail(&r->err, 6);
	}
	for (i = 0; argv[i]; i++)
		free(argv[i]);
}

/* Setup (in a fresh temp dir t->nssdb), run and classify one probe for one target. */
static enum status execute(const struct probe *p, struct target *t, char *why)
{
	static unsigned seq;
	enum status st = UNKNOWN;
	struct run r = { 0 };
	int fail = 0;

	if (p->setup[0][0]) {
		t->nssdb = xasprintf("%s/db%u", g_tmpdir, seq++);
		if ((fail = mkdir(t->nssdb, 0700)))
			verdict(UNKNOWN, why, "mkdir %s: %s", t->nssdb, strerror(errno));
	}
	for (size_t i = 0; !fail && i < ARRAY_SIZE(p->setup) && p->setup[i][0]; i++) {
		run_template(p->setup[i], t, &r);
		if ((fail = r.rc || r.timed_out))
			verdict(UNKNOWN, why, "setup: %s exit %d: %s", p->setup[i][0], r.rc,
				pick_line(&r.err, NULL));
		run_free(&r);
	}
	if (!fail) {
		if (p->argv[0])
			run_template(p->argv, t, &r);
		if (g_stop)
			st = verdict(UNKNOWN, why, "interrupted");
		else if (r.timed_out)
			st = verdict(UNKNOWN, why, "no result within %d s, killed", opt_timeout + 1);
		else
			st = p->classify(p->argv[0] ? &r : NULL, t, why);
	}
	run_free(&r);
	if (t->nssdb)
		rm_tree(t->nssdb);
	free(t->nssdb);
	t->nssdb = NULL;
	return st;
}

static const char *missing_tool(const struct probe *p)
{
	static char why[WHY];
	const char *tools[] = { p->argv[0], p->setup[0][0], p->setup[1][0] };

	for (size_t i = 0; i < ARRAY_SIZE(tools); i++) {
		if (tools[i] && !tool_exists(tools[i])) {
			snprintf(why, sizeof(why), "%s not installed", tools[i]);
			return why;
		}
	}
	return NULL;
}

/* Control of client `tool` for endpoint e, run once: trusting only the
 * endpoint's root it must accept, trusting only another root it must reject.
 * CTRL_NONE (no control possible): its rejections prove nothing. */
static const struct ctl *control(const char *tool, size_t e)
{
	static const struct ctl none = { CTRL_NONE, "no control defined" };
	const struct endpoint *ep = &endpoints[e];
	const char *miss;
	struct ctl *c;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(probes); i++)
		if ((probes[i].flags & F_CONTROL) && !strcmp(probes[i].argv[0], tool))
			break;
	if (i == ARRAY_SIZE(probes))
		return &none;
	if ((c = &ctls[i][e])->state != CTRL_UNSET)
		return c;
	if ((miss = missing_tool(&probes[i])) != NULL) {
		c->state = CTRL_NONE;
		snprintf(c->why, WHY, "no control (%s)", miss);
	}
	for (size_t k = 0; k < 2 && !c->state; k++) {
		const struct root *r = &roots[((size_t)ep->root + k) % NROOTS];
		struct item it = { r->tmp_pem, "embedded root", NULL };
		struct target t = { ep, r, &it, NULL };
		char why[WHY];

		if (execute(&probes[i], &t, why) != (k ? PATCHED : VULNERABLE)) {
			c->state = CTRL_FAILED;
			snprintf(c->why, WHY, "%s control failed (trusting only %s): %.180s", tool,
				 r->id, why);
		}
	}
	if (!c->state)
		c->state = CTRL_OK;
	printf("%scontrol:%s %s @ %s -> %s%s%s\n", C(BLUE), C(RESET), tool, ep->host,
	       C(c->state == CTRL_OK ? GREEN : YELLOW), c->state == CTRL_OK ? "OK" : c->why,
	       C(RESET));
	return c;
}

static int client_ok(const char *tool)
{
	for (size_t e = 0; e < ARRAY_SIZE(endpoints); e++)
		if (control(tool, e)->state != CTRL_OK)
			return 0;
	return 1;
}

static void probe_target(const struct probe *p, struct target *t, size_t e)
{
	const struct ctl *c = p->flags & F_NET ? control(p->argv[0], e) : NULL;
	char *store = expand(p->store, t), why[WHY], res[WHY];
	enum status st;

	if (c && c->state == CTRL_FAILED)
		st = verdict(UNKNOWN, why, "%s", c->why);
	else if ((st = execute(p, t, res)) == PATCHED && c && c->state == CTRL_NONE)
		st = verdict(UNKNOWN, why, "%.120s, but %.120s", res, c->why);
	else
		snprintf(why, sizeof(why), "%s", res);
	report(st, store, t->root, t->ep, "%s", why);
	free(store);
}

static void run_probe(const struct probe *p)
{
	const struct itemlist *l = p->iter == PER_BUNDLE ? &bundles : p->iter == PER_CKBI ? &ckbis : NULL;
	size_t n = p->flags & F_NET ? ARRAY_SIZE(endpoints) : NROOTS;
	const char *why = NULL;
	struct target t = { 0 };

	if (p->iter == CONTROL_ONLY)
		return;
	if (l && !l->n)
		why = l == &bundles ? "no CA bundle files found" : "no libnssckbi.so found";
	else if (!(why = p->skip ? p->skip() : NULL))
		why = missing_tool(p);
	if (why) {
		char *store = expand(p->store, &t);

		report(SKIPPED, store, NULL, NULL, "%s", why);
		free(store);
		return;
	}
	for (size_t i = 0; i < (l ? l->n : 1) && !g_stop; i++) {
		for (size_t k = 0; k < n && !g_stop; k++) {
			t.item = l ? &l->v[i] : NULL;
			t.ep = p->flags & F_NET ? &endpoints[k] : NULL;
			t.root = &roots[t.ep ? (size_t)t.ep->root : k];
			probe_target(p, &t, k);
		}
	}
}

static void discover_env(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(bundle_envs); i++) {
		const char *v = getenv(bundle_envs[i].var);

		if (v && *v)
			item_add(&bundles, v, bundle_envs[i].origin);
	}
}

/* Label the file gRPC C-core loads by default (unless the application overrides it). */
static void discover_grpc(void)
{
	const char *nosys = getenv("GRPC_NOT_USE_SYSTEM_SSL_ROOTS");
	const char *env = getenv("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH");
	int sys = !nosys || !*nosys || !strcmp(nosys, "0") || !strcmp(nosys, "false");

	if (env && *env)	/* handled via bundle_envs[] */
		return;
	for (size_t i = 0; sys && i < ARRAY_SIZE(bundle_globs); i++) {
		if (bundle_globs[i].grpc && is_regular(bundle_globs[i].glob)) {
			item_add(&bundles, bundle_globs[i].glob, "used by gRPC C-core");
			return;
		}
	}
	if (is_regular("/usr/share/grpc/roots.pem"))
		item_add(&bundles, "/usr/share/grpc/roots.pem", "used by gRPC C-core");
}

/* Ask python3 which files certifi, pip's vendored certifi and grpcio use. */
static void discover_python(void)
{
	static const char code[] =
		"import os\n"
		"for tag, get in (('used by certifi', lambda: __import__('certifi').where()),\n"
		"  ('used by pip', lambda: __import__('pip._vendor.certifi', fromlist=['x']).where()),\n"
		"  ('used by grpcio (always)', lambda: os.path.join(os.path.dirname(\n"
		"    __import__('grpc').__file__), '_cython', '_credentials', 'roots.pem'))):\n"
		"    try: p = get()\n"
		"    except Exception: continue\n"
		"    if os.path.isfile(p): print(tag + '\\t' + p)\n";
	const char *const argv[] = { "python3", "-c", code, NULL };
	struct target t = { 0 };
	struct run r;
	char *line, *save = NULL, *tab;

	if (!tool_exists("python3"))
		return;
	run_template(argv, &t, &r);
	line = r.rc == 0 && r.out.p ? strtok_r(r.out.p, "\n", &save) : NULL;
	for (; line; line = strtok_r(NULL, "\n", &save)) {
		if ((tab = strchr(line, '\t')) != NULL) {
			*tab = '\0';
			item_add(&bundles, tab + 1, line);
		}
	}
	run_free(&r);
}

static void online(void)
{
	make_tmpdir();
	for (size_t i = 0; i < NROOTS; i++) {
		char *name = xasprintf("%s.pem", roots[i].id);

		roots[i].tmp_pem = write_tmp(name, roots[i].pem, strlen(roots[i].pem));
		free(name);
	}
	for (size_t i = 0; i < ARRAY_SIZE(bundle_globs); i++)
		add_glob(&bundles, bundle_globs[i].glob, bundle_globs[i].origin);
	for (size_t i = 0; i < ARRAY_SIZE(discovery_hooks) && !g_stop; i++)
		discovery_hooks[i]();
	for (size_t i = 0; i < ARRAY_SIZE(ckbi_globs); i++)
		add_glob(&ckbis, ckbi_globs[i], "NSS builtins");
	printf("%s== online ==%s\n", C(BLUE), C(RESET));
	for (size_t i = 0; i < ARRAY_SIZE(endpoints); i++)
		printf("%sendpoint%s %s:%s needs %s%s%s\n", C(BLUE), C(RESET), endpoints[i].host,
		       endpoints[i].port, C(MAGENTA), roots[endpoints[i].root].id, C(RESET));
	for (size_t i = 0; i < bundles.n + ckbis.n; i++) {
		const struct item *it = i < bundles.n ? &bundles.v[i] : &ckbis.v[i - bundles.n];
		char *path = printable(it->path);

		printf("%s%s%s %s [%s]\n", C(BLUE), i < bundles.n ? "bundle  " : "module  ", C(RESET),
		       path, it->origin);
		free(path);
	}
	for (size_t i = 0; i < ARRAY_SIZE(probes) && !g_stop; i++)
		run_probe(&probes[i]);
}

/* ------------------------------------------------------------------ offline search */

struct search {
	const struct searcher *s;
	struct strv pats, cand, batch;
	size_t batch_bytes, unreadable;
	char *bad;			/* the first unreadable path and why */
	char failed[WHY];		/* why the search is incomplete, "" if it is not */
};

static void note_unreadable(struct search *se, const char *what, int err)
{
	if (!se->unreadable++)
		se->bad = err ? xasprintf("%s: %s", what, strerror(err)) : xstrdup(what);
}

/* Run the searcher on paths.  Its "PROG: /path: reason" lines are per-file errors
 * (vanished files are ignored); any other message means the search went wrong. */
static void search_run(struct search *se, char *const *paths, size_t npaths)
{
	struct strv argv = { 0 };
	char *tool = find_tool(se->s->argv[0]), *line, *save = NULL;
	size_t i, fixed;
	struct run r;

	strv_add(&argv, tool ? tool : xstrdup(se->s->argv[0]));
	for (i = 1; i < MAX_ARGV && se->s->argv[i]; i++)
		strv_add(&argv, xstrdup(se->s->argv[i]));
	if (opt_xdev && se->s->xdev)
		strv_add(&argv, xstrdup(se->s->xdev));
	for (i = 0; i < se->pats.n; i++) {
		strv_add(&argv, xstrdup("-e"));
		strv_add(&argv, xstrdup(se->pats.v[i]));
	}
	strv_add(&argv, xstrdup("--"));
	for (fixed = argv.n, i = 0; i < npaths; i++)
		strv_add(&argv, xstrdup(paths[i]));
	if (opt_verbose)
		print_argv(argv.v, npaths > 32 ? fixed : argv.n, npaths > 32 ? npaths : 0);
	run_cmd(argv.v, 0, &r);
	if (opt_verbose)
		print_tail(&r.err, 6);
	for (line = r.err.p ? strtok_r(r.err.p, "\n", &save) : NULL; line;
	     line = strtok_r(NULL, "\n", &save)) {
		const char *msg = strstr(line, ": ");

		if (msg && msg[2] == '/') {
			if (!strstr(msg, "No such file or directory") && !strstr(msg, "Not a directory"))
				note_unreadable(se, msg + 2, 0);
		} else if (!*se->failed) {
			snprintf(se->failed, WHY, "%s", line);
		}
	}
	if (!*se->failed && (r.rc < 0 || r.rc > 2 || (r.rc == 2 && !r.err.len) ||
			     r.out.truncated || r.err.truncated))
		snprintf(se->failed, WHY, "%s exit %d%s", se->s->name, r.rc,
			 r.out.truncated ? ", output truncated" : "");
	for (const char *p = buf_str(&r.out), *end = p + r.out.len, *sep; p < end; p = sep + 1) {
		if (!(sep = memchr(p, se->s->sep, (size_t)(end - p))))
			sep = end;
		if (sep > p)
			strv_add(&se->cand, xasprintf("%.*s", (int)(sep - p), p));
	}
	run_free(&r);
	strv_free(&argv);
}

static void batch_flush(struct search *se)
{
	if (se->batch.n)
		search_run(se, se->batch.v, se->batch.n);
	strv_free(&se->batch);
	se->batch_bytes = 0;
}

/* Feed every regular file below path to a non-recursive searcher (no symlinks).
 * Directories are read and closed before descending: one fd at a time. */
static void walk(struct search *se, const char *path, dev_t dev)
{
	struct strv sub = { 0 };
	struct stat st;
	struct dirent *e;
	DIR *d;

	if (g_stop || lstat(path, &st)) {
		if (!g_stop && errno != ENOENT)
			note_unreadable(se, path, errno);
		return;
	}
	if (opt_xdev && st.st_dev != dev)
		return;
	if (S_ISREG(st.st_mode) && strchr(path, '\n')) {	/* grep -l can't return it */
		strv_add(&se->cand, xstrdup(path));
	} else if (S_ISREG(st.st_mode)) {
		strv_add(&se->batch, xstrdup(path));
		if ((se->batch_bytes += strlen(path) + 1) >= 64 * 1024 || se->batch.n >= 512)
			batch_flush(se);
	} else if (S_ISDIR(st.st_mode)) {
		if (!(d = opendir(path))) {
			if (errno != ENOENT)
				note_unreadable(se, path, errno);
			return;
		}
		while ((e = readdir(d)) != NULL)
			if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
				strv_add(&sub, xasprintf("%s/%s", path, e->d_name));
		closedir(d);
		for (size_t i = 0; i < sub.n; i++)
			walk(se, sub.v[i], dev);
		strv_free(&sub);
	}
}

static void scan(struct search *se, char *const *starts, size_t n, dev_t dev)
{
	if (se->s->recursive) {
		search_run(se, starts, n);
		return;
	}
	for (size_t i = 0; i < n; i++)
		walk(se, starts[i], dev);
	batch_flush(se);
}

/* ROOT itself, or the entries of the live "/" minus live_skip[] and top-level
 * symlinks (merged-/usr links would be scanned twice). */
static void start_paths(const char *root, struct strv *out, dev_t dev)
{
	struct dirent *e;
	struct stat st;
	DIR *d;

	if (strcmp(root, "/") || !(d = opendir("/"))) {
		strv_add(out, xstrdup(root));
		return;
	}
	while ((e = readdir(d)) != NULL) {
		char *p = xasprintf("/%s", e->d_name);
		size_t i;

		for (i = 0; i < ARRAY_SIZE(live_skip) && strcmp(e->d_name, live_skip[i]); i++)
			;
		if (i < ARRAY_SIZE(live_skip) || !strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
		    lstat(p, &st) || S_ISLNK(st.st_mode) || (opt_xdev && st.st_dev != dev))
			free(p);
		else
			strv_add(out, p);
	}
	closedir(d);
	if (out->n)
		qsort(out->v, out->n, sizeof(*out->v), cmp_str);
}

/* The searcher must list a PEM text file and, per root, a binary with its DER
 * after NUL bytes (busybox grep ignores text after a NUL within a line; both
 * DERs have a newline, and no NUL, before their CN). */
static const char *selftest(struct search *se)
{
	static char why[WHY];
	struct strv files = { 0 };
	struct buf pem = { 0 };
	struct stat st;

	make_tmpdir();
	for (size_t i = 0; i < NROOTS; i++) {
		struct buf bin = { 0 };
		char name[32];

		buf_add(&pem, roots[i].pem, strlen(roots[i].pem));
		buf_add(&bin, i % 2 ? "\376\377" : "\377\376", 2);	/* UTF-16 BOMs */
		buf_add(&bin, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0", 16);
		buf_add(&bin, roots[i].der, roots[i].der_len);
		snprintf(name, sizeof(name), "bin%zu", i);
		strv_add(&files, write_tmp(name, bin.p, bin.len));
		free(bin.p);
	}
	strv_add(&files, write_tmp("pem.txt", pem.p, pem.len));
	free(pem.p);
	scan(se, &g_tmpdir, 1, stat(g_tmpdir, &st) ? 0 : st.st_dev);
	snprintf(why, sizeof(why), "%s", se->failed);
	for (size_t i = 0, k; !*why && i < files.n; i++) {
		for (k = 0; k < se->cand.n && strcmp(se->cand.v[k], files.v[i]); k++)
			;
		if (k == se->cand.n)
			snprintf(why, sizeof(why), "did not find the test file %s",
				 strrchr(files.v[i], '/') + 1);
	}
	strv_free(&se->cand);
	strv_free(&files);
	free(se->bad);
	se->bad = NULL;
	se->unreadable = 0;
	*se->failed = '\0';
	rm_tree(g_tmpdir);	/* before the scan, which must not find it */
	free(g_tmpdir);
	g_tmpdir = NULL;
	return *why ? why : NULL;
}

/* The first installed searcher (or --searcher) that passes the self-test. */
static const struct searcher *pick_searcher(struct search *se, struct buf *tried)
{
	for (size_t i = 0; i < ARRAY_SIZE(searchers) && !g_stop; i++) {
		const char *why;
		char *s;

		if (opt_searcher && strcmp(opt_searcher, searchers[i].name))
			continue;
		se->s = &searchers[i];
		if (!(why = tool_exists(se->s->argv[0]) ? selftest(se) : "not installed"))
			return se->s;
		s = xasprintf("%s%s: %s", tried->len ? "; " : "", se->s->name, why);
		buf_add(tried, s, strlen(s));
		free(s);
	}
	return se->s = NULL;
}

/* Report the hits of one file; returns the roots it decided (VULNERABLE/UNKNOWN
 * or judged online later). */
static unsigned offline_report(const char *path, const unsigned *hits, int binary, int feed)
{
	const char *base = strrchr(path, '/') ? strrchr(path, '/') + 1 : path;
	const struct path_class *pc = NULL;
	unsigned decided = 0;

	for (size_t c = 0; c < ARRAY_SIZE(path_classes) && !pc; c++)
		if (path_classes[c].base ? !strncmp(base, path_classes[c].match,
						    strlen(path_classes[c].match)) :
		    strstr(path, path_classes[c].match) != NULL)
			pc = &path_classes[c];
	for (size_t i = 0; i < NROOTS; i++) {
		const struct root *r = &roots[i];
		int fed = pc && feed && pc->feed;

		if (!hits[i])
			continue;
		if (pc) {
			report(fed ? SKIPPED : pc->st, path, r, NULL, "%s copy; %s%s",
			       hits[i] & HIT_DER ? "DER" : "PEM", pc->why, fed ? ", judged below" : "");
			if (fed)
				item_add(pc->feed, path, "found offline");
			decided |= fed || pc->st == UNKNOWN ? 1u << i : 0;
			continue;
		}
		if (hits[i] & HIT_DER)
			report(VULNERABLE, path, r, NULL, "DER copy of %s embedded", r->cn);
		if ((hits[i] & HIT_PEM) && !binary) {
			report(VULNERABLE, path, r, NULL, "PEM bundle trusts %s", r->cn);
			if (feed)
				item_add(&bundles, path, "found offline");
		} else if (hits[i] & (HIT_PEM | HIT_PEM_ESC)) {
			report(VULNERABLE, path, r, NULL, "PEM copy of %s embedded (%s)", r->cn,
			       binary ? "binary" : "escaped, e.g. source code or JSON");
		}
		if (hits[i] & HIT_NOT_TLS)
			report(PATCHED, path, r, NULL, "OpenSSL TRUSTED CERTIFICATE entry for %s "
			       "excludes TLS server auth", r->cn);
		decided |= hits[i] & ~(unsigned)HIT_NOT_TLS ? 1u << i : 0;
	}
	return decided;
}

/* Confirm every candidate; returns the roots decided by some file. */
static unsigned confirm_candidates(struct search *se, int feed)
{
	unsigned decided = 0;

	if (se->cand.n)
		qsort(se->cand.v, se->cand.n, sizeof(*se->cand.v), cmp_str);
	for (size_t i = 0; i < se->cand.n && !g_stop; i++) {
		unsigned hits[NROOTS] = { 0 }, any = 0;
		int binary = 0;

		if (i && !strcmp(se->cand.v[i], se->cand.v[i - 1]))
			continue;
		if (confirm_file(se->cand.v[i], hits, &binary)) {
			if (errno != ENOENT) {	/* else it vanished: nothing to judge */
				note_unreadable(se, se->cand.v[i], errno);
				report(UNKNOWN, se->cand.v[i], NULL, NULL, "unreadable: %s", strerror(errno));
			}
			continue;
		}
		for (size_t k = 0; k < NROOTS; k++)
			any |= hits[k];
		if (any)
			decided |= offline_report(se->cand.v[i], hits, binary, feed);
		else if (opt_verbose)
			printf("%s    candidate rejected (no exact DER/PEM match): %s%s\n", C(GREY),
			       se->cand.v[i], C(RESET));
	}
	return decided;
}

static void offline(const char *root, int feed)
{
	struct search se = { 0 };
	struct strv starts = { 0 };
	struct buf tried = { 0 };
	unsigned decided;
	struct stat st;
	dev_t dev;
	char *store;

	for (size_t i = 0; i < NROOTS; i++) {
		strv_add(&se.pats, xstrdup(roots[i].cn));
		if (strcmp(roots[i].label, roots[i].cn))
			strv_add(&se.pats, xstrdup(roots[i].label));
		strv_add(&se.pats, xstrdup(roots[i].b64));
	}
	if (!pick_searcher(&se, &tried))
		for (size_t i = 0; i < NROOTS && !g_stop; i++)
			report(UNKNOWN, "offline search", &roots[i], NULL, "no usable searcher (%s)",
			       buf_str(&tried));
	if (!se.s || g_stop)
		goto out;
	printf("%s== offline: searching %s with %s (a whole system takes minutes) ==%s\n", C(BLUE),
	       root, se.s->name, C(RESET));
	dev = stat(root, &st) ? 0 : st.st_dev;
	start_paths(root, &starts, dev);
	scan(&se, starts.v, starts.n, dev);
	for (size_t i = 0; i < bundles.n; i++)	/* --bundle files */
		strv_add(&se.cand, xstrdup(bundles.v[i].path));
	decided = confirm_candidates(&se, feed);
	store = xasprintf("offline search of %s (%s)", root, se.s->name);
	for (size_t i = 0; i < NROOTS && !g_stop; i++) {
		if (*se.failed)
			report(UNKNOWN, store, &roots[i], NULL, "search incomplete: %s", se.failed);
		else if (se.unreadable && !(decided & 1u << i))
			report(UNKNOWN, store, &roots[i], NULL, "none in readable files; %zu path(s) "
			       "unreadable, e.g. %s", se.unreadable, se.bad);
		else if (!(decided & 1u << i))
			report(PATCHED, store, &roots[i], NULL, "no trusted copy found");
	}
	if (se.unreadable && !*se.failed)
		printf("%snote:%s %zu path(s) unreadable, e.g. %s; run as root for a complete scan\n",
		       C(YELLOW), C(RESET), se.unreadable, se.bad);
	free(store);
out:
	free(se.bad);
	free(tried.p);
	strv_free(&starts);
	strv_free(&se.pats);
	strv_free(&se.cand);
}

/* ------------------------------------------------------------------ main */

static const char usage_text[] =
"Usage: certstore-check [-v] [--timeout SEC] [--bundle FILE]... [--xdev]\n"
"                       [--offline[=ROOT] | --all[=ROOT]] [--searcher NAME]\n"
"                       [--color[=WHEN] | --no-color]\n"
"Finds trust stores that still trust \"emSign ECC Root CA - G3\" or Sectigo's\n"
"\"AAA Certificate Services\" (NSS: \"Comodo AAA Services root\"), the roots of\n"
"the compromised eMudhra intermediates (Oct 2026).\n"
"Modes:\n"
"  (default)        online: curl with its default store and with --cacert for\n"
"                   every CA bundle found (system, gRPC, certifi, pip, grpcio,\n"
"                   $SSL_CERT_FILE etc., --bundle); openssl s_client if curl is\n"
"                   missing or broken; NSS tstclnt (builtins, /etc/pki/nssdb);\n"
"                   certutil+modutil on each libnssckbi.so.  Each client is first\n"
"                   controlled per endpoint: trusting only the matching embedded\n"
"                   root it must accept, only another root reject, else its\n"
"                   results are UNKNOWN.  Without a working client, bundles and\n"
"                   libnssckbi.so are checked statically.\n"
"  --offline[=ROOT] only search ROOT (default /) for copies of the roots with rg,\n"
"                   else grep (GNU or busybox), after a self-test; every hit is\n"
"                   confirmed by exact DER.  A whole system takes minutes.\n"
"  --all[=ROOT]     both; with ROOT=/ bundles and libnssckbi.so found offline\n"
"                   are also checked online.\n"
"Options:\n"
"  --timeout SEC    per probe, 1..86400 (default 15); clients are killed after\n"
"                   SEC+1.  The offline search has no time limit.\n"
"  --bundle FILE    also check this CA bundle file (repeatable, also offline)\n"
"  --searcher NAME  rg or grep (default: the first passing its self-test)\n"
"  --xdev           offline: stay on ROOT's filesystem\n"
"  -v               print every command line and the tail of its stderr (grey)\n"
"  --color[=WHEN]   always, never or auto (default): colors only on a terminal\n"
"                   and with $NO_COLOR unset or empty; --no-color = never\n"
"Statuses: VULNERABLE trusts a compromised root; PATCHED rejected, removed or\n"
"distrusted; UNKNOWN undecided (network, failed control, tool error, unreadable\n"
"paths, presence without trust state); SKIPPED not applicable.\n"
"Exit codes: 0 nothing VULNERABLE/UNKNOWN, 1 something VULNERABLE, 2 something\n"
"UNKNOWN but nothing VULNERABLE, 3 usage/internal error, 130 interrupted.\n"
"Limitations:\n"
" - Offline: no look into compressed files, archives (jar, zip, wheel, apk,\n"
"   cpio) or nested images: extract them first.  /proc /sys /dev /run\n"
"   /.snapshots of the live / are skipped, symlinks never followed.  Unreadable\n"
"   paths make the result UNKNOWN: run as root.\n"
" - Offline hits prove presence: PEM bundles trust what they contain (OpenSSL\n"
"   TRUSTED CERTIFICATE aux trust is honoured); embedded DER/PEM copies are\n"
"   VULNERABLE (check how the program uses them); libnssckbi.so and NSS dbs\n"
"   also keep distrusted roots (UNKNOWN unless judged online); blocklist\n"
"   entries are PATCHED, CA source files SKIPPED.  This tool's own files and\n"
"   builds are reported too.\n"
" - The static NSS check reads trust flags, not \"distrust after\" dates (tstclnt\n"
"   honours them).  gRPC cannot be tested live (endpoints lack h2): the files\n"
"   gRPC C-core and grpcio load are probed.  Roots compiled into programs are\n"
"   only found offline.\n";

/* The help text, its headings ("Usage:", "Modes:" ...) bold if color is set. */
static void usage(FILE *f, int color)
{
	for (const char *p = usage_text, *nl; *p; p = nl + 1) {
		size_t h = strspn(p, " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

		nl = strchr(p, '\n');
		if (color && *p != ' ' && p[h] == ':') {
			fprintf(f, "%s%.*s%s", sgr[BOLD], (int)h + 1, p, sgr[RESET]);
			p += h + 1;
		}
		fprintf(f, "%.*s\n", (int)(nl - p), p);
	}
}

/* "--name VALUE" or "--name=VALUE"; an optional VALUE must not start with '-' */
static int take_arg(int *i, int argc, char **argv, const char *name, const char **val,
		    int optional)
{
	const char *a = argv[*i];
	size_t n = strlen(name);

	if (strncmp(a, name, n) || (a[n] && a[n] != '='))
		return 0;
	if (a[n] == '=')
		*val = a + n + 1;
	else if (*i + 1 < argc && (!optional || argv[*i + 1][0] != '-'))
		*val = argv[++*i];
	else if (!optional)
		die("%s needs an argument", name);
	return 1;
}

static void cleanup(void)	/* atexit: also runs after die() */
{
	if (g_tmpdir)
		rm_tree(g_tmpdir);
	free(g_tmpdir);
	g_tmpdir = NULL;
}

enum { M_ONLINE = 1, M_OFFLINE = 2 };

/* Options into opt_* and bundles; returns the M_* mode, *root for offline. */
static int parse_args(int argc, char **argv, const char **root)
{
	const char *val = NULL;
	int mode = 0, help = 0;
	char *end;
	long n;

	for (int i = 1; i < argc; i++, val = NULL) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			help = 1;	/* after the loop: a later --color applies */
		} else if (!strcmp(argv[i], "--no-color")) {
			set_color("never");
		} else if (take_arg(&i, argc, argv, "--color", &val, 1)) {
			if (set_color(val ? val : "always"))
				die("--color: WHEN is always, never or auto");
		} else if (!strcmp(argv[i], "-v")) {
			opt_verbose = 1;
		} else if (!strcmp(argv[i], "--xdev")) {
			opt_xdev = 1;
		} else if (take_arg(&i, argc, argv, "--all", root, 1)) {
			mode |= M_ONLINE | M_OFFLINE;
		} else if (take_arg(&i, argc, argv, "--offline", root, 1)) {
			mode |= M_OFFLINE;
		} else if (take_arg(&i, argc, argv, "--timeout", &val, 0)) {
			errno = 0;
			n = strtol(val, &end, 10);
			if (errno || end == val || *end || n < 1 || n > 86400)
				die("--timeout needs 1..86400 seconds");
			opt_timeout = (int)n;
		} else if (take_arg(&i, argc, argv, "--bundle", &val, 0)) {
			if (!is_regular(val))
				die("--bundle %s: not a regular file", val);
			item_add(&bundles, val, "--bundle");
		} else if (take_arg(&i, argc, argv, "--searcher", &val, 0)) {
			size_t k;

			for (k = 0; k < ARRAY_SIZE(searchers) && strcmp(val, searchers[k].name); k++)
				;
			if (k == ARRAY_SIZE(searchers))
				die("--searcher: unknown searcher '%s'", val);
			opt_searcher = val;
		} else {
			fprintf(stderr, "%scertstore-check:%s unknown argument '%s'\n\n", E(RED),
				E(RESET), argv[i]);
			usage(stderr, g_color[2]);
			exit(3);
		}
	}
	if (help) {
		usage(stdout, g_color[1]);
		exit(0);
	}
	return mode ? mode : M_ONLINE;
}

int main(int argc, char **argv)
{
	static const int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGALRM, SIGUSR1, SIGUSR2 };
	const char *root = "/";
	char real_root[PATH_MAX] = "/";
	struct sigaction sa;
	int mode, fd;

	while ((fd = open("/dev/null", O_RDWR)) >= 0 && fd < 3)	/* children rely on fds 0-2 */
		;
	if (fd > 2)
		close(fd);
	set_color("auto");
	mode = parse_args(argc, argv, &root);
	if ((mode & M_OFFLINE) && !realpath(root, real_root))
		die("cannot access %s: %s", root, strerror(errno));
	setenv("LC_ALL", "C", 1);	/* children: messages we can parse */
	unsetenv("GREP_OPTIONS");
	unsetenv("GREP_COLOR");		/* GNU grep would warn on stderr */

	init_roots();
	if (stat("/proc/self/exe", &g_self))
		memset(&g_self, 0, sizeof(g_self));	/* dev 0, inode 0: matches no file */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;	/* no SA_RESTART: poll()/waitpid() return EINTR */
	sigemptyset(&sa.sa_mask);
	for (size_t i = 0; i < ARRAY_SIZE(sigs); i++)
		sigaction(sigs[i], &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
	atexit(cleanup);

	printf("%sChecking trust in:%s", C(BOLD), C(RESET));
	for (size_t i = 0; i < NROOTS; i++)
		printf("%s \"%s\" [%s%s%s]", i ? "," : "", roots[i].cn, C(MAGENTA), roots[i].id,
		       C(RESET));
	putchar('\n');
	if (mode & M_OFFLINE)	/* first, so the online temp files are not found */
		offline(real_root, (mode & M_ONLINE) && !strcmp(real_root, "/"));
	if ((mode & M_ONLINE) && !g_stop)
		online();
	cleanup();
	if (g_stop) {
		fprintf(stderr, "%scertstore-check:%s interrupted\n", E(YELLOW), E(RESET));
		return 130;
	}
	return summary();
}
