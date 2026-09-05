package auth

import (
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
)

const (
	// SessionCookieName carries the session token for the SPA.
	SessionCookieName = "tracker_session"
	// APIKeyHeader carries an API key.
	APIKeyHeader = "X-Api-Key"
)

// Credentials are the raw secrets found on a request, before any lookup.
type Credentials struct {
	APIKey       string
	SessionToken string
}

// Empty reports whether no credential was presented.
func (c Credentials) Empty() bool { return c.APIKey == "" && c.SessionToken == "" }

// CredentialsFromHTTP extracts credentials in priority order:
// X-Api-Key header, Authorization bearer, session cookie.
func CredentialsFromHTTP(r *http.Request) Credentials {
	if v := strings.TrimSpace(r.Header.Get(APIKeyHeader)); v != "" {
		return Credentials{APIKey: v}
	}
	if c, ok := fromBearer(r.Header.Get("Authorization")); ok {
		return c
	}
	if ck, err := r.Cookie(SessionCookieName); err == nil && ck.Value != "" {
		return Credentials{SessionToken: ck.Value}
	}
	return Credentials{}
}

// CredentialsFromMetadata extracts credentials from gRPC metadata.
func CredentialsFromMetadata(md metadata.MD) Credentials {
	first := func(key string) string {
		if v := md.Get(key); len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	if v := first("x-api-key"); v != "" {
		return Credentials{APIKey: v}
	}
	if c, ok := fromBearer(first("authorization")); ok {
		return c
	}
	return Credentials{}
}

func fromBearer(header string) (Credentials, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return Credentials{}, false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return Credentials{}, false
	}
	if IsAPIKey(token) {
		return Credentials{APIKey: token}, true
	}
	return Credentials{SessionToken: token}, true
}

// SessionCookie builds the cookie carrying a session token.
func SessionCookie(token string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
	}
}

// ClearSessionCookie builds the cookie that removes the session.
func ClearSessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	}
}

// ClientIP returns the peer address, honouring X-Forwarded-For only when the
// deployment declares a trusted reverse proxy.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
