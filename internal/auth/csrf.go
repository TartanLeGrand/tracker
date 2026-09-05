package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// IsCrossSite reports whether a browser request was initiated from another
// site. It is the CSRF guard for the session cookie: that cookie is
// SameSite=Lax, so a browser still attaches it to a top level cross-site GET
// navigation, and the API exposes at least one write behind a GET binding
// (UnLock). A cross-site request must therefore not act as the logged in user.
//
// Sec-Fetch-Site is authoritative when present. Only same-origin, same-site
// and none are accepted; cross-site and any other value are treated as
// cross-site, because browsers are the only clients that send the header and
// an unrecognised value is safest handled as untrusted.
//
// Without Sec-Fetch-Site, an Origin header is compared to the expected origin:
// publicURL (AUTH_PUBLIC_URL) when configured, otherwise the request scheme
// and Host. X-Forwarded-Proto is honoured for the scheme only when trustProxy
// is on, since a client can set it otherwise.
//
// A request carrying neither header comes from a non browser client (curl, a
// script, the MCP server). Such a client cannot be tricked into replaying a
// cookie it does not hold, so it is not cross-site.
func IsCrossSite(r *http.Request, publicURL string, trustProxy bool) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "":
		// No Sec-Fetch-Site, fall back to the Origin check below.
	case "same-origin", "same-site", "none":
		return false
	default:
		return true
	}

	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	return !strings.EqualFold(strings.TrimRight(origin, "/"), expectedOrigin(r, publicURL, trustProxy))
}

// expectedOrigin is the scheme://host[:port] a same-origin request carries.
func expectedOrigin(r *http.Request, publicURL string, trustProxy bool) string {
	if publicURL != "" {
		if u, err := url.Parse(publicURL); err == nil && u.Scheme != "" && u.Host != "" {
			return strings.ToLower(u.Scheme + "://" + u.Host)
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if trustProxy {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			// Same rule as X-Forwarded-For: a proxy chain appends, so the
			// last entry is the one the trusted proxy wrote.
			parts := strings.Split(proto, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if v := strings.TrimSpace(parts[i]); v != "" {
					scheme = strings.ToLower(v)
					break
				}
			}
		}
	}
	return strings.ToLower(scheme + "://" + r.Host)
}
