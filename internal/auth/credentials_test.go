package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestCredentialsFromHTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.True(t, CredentialsFromHTTP(r).Empty())

	r.Header.Set("X-Api-Key", " trk_abcdefgh_secret ")
	assert.Equal(t, Credentials{APIKey: "trk_abcdefgh_secret"}, CredentialsFromHTTP(r))

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer trk_abcdefgh_secret")
	assert.Equal(t, Credentials{APIKey: "trk_abcdefgh_secret"}, CredentialsFromHTTP(r))

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "bearer eyJ.jwt")
	assert.Equal(t, Credentials{SessionToken: "eyJ.jwt"}, CredentialsFromHTTP(r))

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie.jwt"})
	assert.Equal(t, Credentials{SessionToken: "cookie.jwt"}, CredentialsFromHTTP(r))

	// Header wins over cookie.
	r.Header.Set("X-Api-Key", "trk_abcdefgh_secret")
	assert.Equal(t, Credentials{APIKey: "trk_abcdefgh_secret"}, CredentialsFromHTTP(r))
}

func TestCredentialsFromMetadata(t *testing.T) {
	assert.True(t, CredentialsFromMetadata(metadata.MD{}).Empty())
	md := metadata.Pairs("authorization", "Bearer eyJ.jwt")
	assert.Equal(t, Credentials{SessionToken: "eyJ.jwt"}, CredentialsFromMetadata(md))
	md = metadata.Pairs("x-api-key", "trk_abcdefgh_secret")
	assert.Equal(t, Credentials{APIKey: "trk_abcdefgh_secret"}, CredentialsFromMetadata(md))
}

func TestSessionCookies(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	c := SessionCookie("tok", expires, true)
	assert.Equal(t, SessionCookieName, c.Name)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, "/", c.Path)
	assert.Greater(t, c.MaxAge, 3500)

	cleared := ClearSessionCookie(false)
	assert.Equal(t, -1, cleared.MaxAge)
	assert.Empty(t, cleared.Value)
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:4444"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	assert.Equal(t, "10.0.0.5", ClientIP(r, false))
	assert.Equal(t, "203.0.113.9", ClientIP(r, true))
}
