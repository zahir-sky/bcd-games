#!/usr/bin/env python3
"""Honor Wine's C:\\Windows\\System32\\drivers\\etc\\hosts (and MADEIRA_HOSTS) in iOS getaddrinfo().

On iOS, ws2_32/unixlib.c calls Apple's getaddrinfo() directly (wrapped by
patch-wine-dns-trace.py in madeira_dns_real()), which never consults Wine's
prefix hosts file (drive_c/windows/system32/drivers/etc/hosts). Games and
private-server launchers (such as SMX FIFA Online 3 resolving APSEODESK172:443)
rely on entries in Windows' hosts file and fail with EAI_NONAME /
COMMON_ERROR_CURL when they are ignored.

This patch extends madeira_dns_real() (under #ifdef WINE_IOS) to check:
  1. Optional MADEIRA_HOSTS env var ("HOST=IP,HOST2=IP2"), case-insensitive
  2. $WINEPREFIX/drive_c/windows/system32/drivers/etc/hosts (and case variants)
before falling back to iOS getaddrinfo().

Usage: patch-wine-ios-hosts.py wine/dlls/ws2_32/unixlib.c   (idempotent)
"""
import sys

path = sys.argv[1]
src = open(path).read()
if "madeira_dns_lookup_hosts" in src:
    print("already patched")
    sys.exit(0)

old = """static int madeira_dns_real( const char *node, const char *service, const struct addrinfo *hints,
                             struct addrinfo **res )
{
    void *pool = objc_autoreleasePoolPush();
    int ret = getaddrinfo( node, service, hints, res );
    objc_autoreleasePoolPop( pool );
    return ret;
}"""

new = r'''#include <strings.h>

static int madeira_dns_lookup_hosts_file( const char *hosts_path, const char *node, char *ip_out, size_t ip_out_sz )
{
    FILE *f;
    char line[1024];
    size_t nlen;

    if (!hosts_path || !*hosts_path || !node || !*node) return 0;
    f = fopen( hosts_path, "r" );
    if (!f) return 0;
    nlen = strlen( node );

    while (fgets( line, sizeof(line), f ))
    {
        char *p = line;
        char *ip_start, *ip_end;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == '\r' || *p == '\n') continue;

        ip_start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '#' && *p != '\r' && *p != '\n') p++;
        ip_end = p;
        if (ip_end == ip_start || (size_t)(ip_end - ip_start) >= ip_out_sz) continue;

        while (*p && *p != '#' && *p != '\r' && *p != '\n')
        {
            char *h_start, *h_end;
            while (*p == ' ' || *p == '\t') p++;
            if (!*p || *p == '#' || *p == '\r' || *p == '\n') break;
            h_start = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '#' && *p != '\r' && *p != '\n') p++;
            h_end = p;
            if ((size_t)(h_end - h_start) == nlen && !strncasecmp( h_start, node, nlen ))
            {
                memcpy( ip_out, ip_start, (size_t)(ip_end - ip_start) );
                ip_out[ip_end - ip_start] = '\0';
                fclose( f );
                return 1;
            }
        }
    }
    fclose( f );
    return 0;
}

static int madeira_dns_lookup_hosts( const char *node, char *ip_out, size_t ip_out_sz )
{
    const char *env_hosts;
    const char *prefix;
    char path[1024];
    static const char *const rels[] = {
        "drive_c/windows/system32/drivers/etc/hosts",
        "drive_c/Windows/System32/drivers/etc/hosts",
        "dosdevices/c:/windows/system32/drivers/etc/hosts",
        "dosdevices/c:/Windows/System32/drivers/etc/hosts",
    };
    size_t i;

    if (!node || !*node) return 0;

    env_hosts = getenv( "MADEIRA_HOSTS" );
    if (env_hosts && *env_hosts)
    {
        const char *p = env_hosts;
        size_t nlen = strlen( node );
        while (*p)
        {
            const char *eq, *end;
            while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';') p++;
            if (!*p) break;
            end = p;
            while (*end && *end != ',' && *end != ';') end++;
            eq = memchr( p, '=', (size_t)(end - p) );
            if (eq && (size_t)(eq - p) == nlen && !strncasecmp( p, node, nlen ))
            {
                size_t vlen = (size_t)(end - (eq + 1));
                while (vlen && (eq[1 + vlen - 1] == ' ' || eq[1 + vlen - 1] == '\t')) vlen--;
                if (vlen > 0 && vlen < ip_out_sz)
                {
                    memcpy( ip_out, eq + 1, vlen );
                    ip_out[vlen] = '\0';
                    return 1;
                }
            }
            p = *end ? end + 1 : end;
        }
    }

    prefix = getenv( "WINEPREFIX" );
    if (!prefix || !*prefix) return 0;
    for (i = 0; i < sizeof(rels) / sizeof(rels[0]); i++)
    {
        int len = snprintf( path, sizeof(path), "%s/%s", prefix, rels[i] );
        if (len > 0 && (size_t)len < sizeof(path) &&
            madeira_dns_lookup_hosts_file( path, node, ip_out, ip_out_sz ))
            return 1;
    }
    return 0;
}

static int madeira_dns_real( const char *node, const char *service, const struct addrinfo *hints,
                             struct addrinfo **res )
{
    char hosts_ip[64];
    void *pool = objc_autoreleasePoolPush();
    int ret;

    if (node && !(hints && (hints->ai_flags & AI_NUMERICHOST)) &&
        madeira_dns_lookup_hosts( node, hosts_ip, sizeof(hosts_ip) ))
    {
        struct addrinfo num_hints;
        if (hints) num_hints = *hints;
        else memset( &num_hints, 0, sizeof(num_hints) );
        num_hints.ai_flags |= AI_NUMERICHOST;
        num_hints.ai_flags &= ~AI_CANONNAME;
        fprintf( stderr, "[dns] madeira-bcd hosts-hit \"%s\" -> \"%s\"\n", node, hosts_ip );
        ret = getaddrinfo( hosts_ip, service, &num_hints, res );
    }
    else
    {
        ret = getaddrinfo( node, service, hints, res );
    }
    objc_autoreleasePoolPop( pool );
    return ret;
}'''

if old not in src:
    sys.exit(f"anchor not found in {path} (run patch-wine-dns-trace.py first)")

src = src.replace(old, new, 1)
open(path, "w").write(src)
print(f"patched {path}")
