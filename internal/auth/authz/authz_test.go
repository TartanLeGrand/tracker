package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bananaops/tracker/internal/auth"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const listEvents = "/tracker.event.v1alpha1.EventService/ListEvents"

func TestCheck(t *testing.T) {
	anon := auth.Anonymous(nil)
	reader := auth.Principal{Kind: auth.KindUser, Username: "r", Permissions: auth.NewPermissionSet(auth.PermEventRead)}

	assert.Equal(t, codes.Unauthenticated, status.Code(Check(anon, listEvents)))
	assert.NoError(t, Check(reader, listEvents))
	assert.Equal(t, codes.PermissionDenied, status.Code(Check(reader, "/tracker.event.v1alpha1.EventService/CreateEvent")))
	assert.Equal(t, codes.PermissionDenied, status.Code(Check(reader, "/tracker.nope.v1/Svc/Method")), "unmapped method is denied")

	anonReader := auth.Anonymous([]auth.Permission{auth.PermEventRead})
	assert.NoError(t, Check(anonReader, listEvents))

	assert.NoError(t, Check(anon, "/tracker.auth.v1alpha1.AuthService/GetAuthConfig"), "public")
	assert.NoError(t, Check(anon, "/tracker.auth.v1alpha1.AuthService/Me"), "public")
	assert.Equal(t, codes.Unauthenticated, status.Code(Check(anon, "/tracker.auth.v1alpha1.AuthService/ListUsers")))
	assert.Equal(t, codes.PermissionDenied, status.Code(Check(reader, "/tracker.auth.v1alpha1.AuthService/ListUsers")))
}

func TestAuthorizeWithoutPrincipalIsAnonymous(t *testing.T) {
	err := Authorize(context.Background())
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "no method in context: unmapped, denied")
}

func TestRequireHTTP(t *testing.T) {
	called := false
	h := RequireHTTP(auth.PermLinksWrite, func(w http.ResponseWriter, r *http.Request, _ map[string]string) { called = true })

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/links", nil), nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called)

	ctx := auth.WithPrincipal(context.Background(), auth.Principal{Kind: auth.KindUser, Permissions: auth.NewPermissionSet(auth.PermLinksRead)})
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/links", nil).WithContext(ctx), nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, called)

	ctx = auth.WithPrincipal(context.Background(), auth.Principal{Kind: auth.KindUser, Permissions: auth.NewPermissionSet(auth.PermLinksWrite)})
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/links", nil).WithContext(ctx), nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called)
}
