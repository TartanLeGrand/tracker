package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func fakeResolver() Resolver {
	return ResolverFunc(func(_ context.Context, c Credentials) Principal {
		if c.APIKey == "trk_abcdefgh_ok" {
			return Principal{Kind: KindAPIKey, Username: "apikey:abcdefgh", Permissions: NewPermissionSet(PermEventRead)}
		}
		return Anonymous(nil)
	})
}

func TestHTTPMiddlewareStoresPrincipal(t *testing.T) {
	var seen Principal
	h := HTTPMiddleware(fakeResolver())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Api-Key", "trk_abcdefgh_ok")
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, KindAPIKey, seen.Kind)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, KindAnonymous, seen.Kind)
}

func TestUnaryInterceptorStoresPrincipal(t *testing.T) {
	var seen Principal
	handler := func(ctx context.Context, req any) (any, error) {
		seen, _ = FromContext(ctx)
		return nil, nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "trk_abcdefgh_ok"))
	_, err := UnaryInterceptor(fakeResolver())(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, handler)
	require.NoError(t, err)
	assert.Equal(t, KindAPIKey, seen.Kind)
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeStream) Context() context.Context { return s.ctx }

func TestStreamInterceptorStoresPrincipal(t *testing.T) {
	var seen Principal
	handler := func(srv any, ss grpc.ServerStream) error {
		seen, _ = FromContext(ss.Context())
		return nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "trk_abcdefgh_ok"))
	err := StreamInterceptor(fakeResolver())(nil, fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/x/Y"}, handler)
	require.NoError(t, err)
	assert.Equal(t, KindAPIKey, seen.Kind)
}
