package auth

import (
	"context"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Resolver turns raw credentials into a principal. It never fails: an invalid
// credential yields the anonymous principal.
type Resolver interface {
	Resolve(ctx context.Context, creds Credentials) Principal
}

// ResolverFunc adapts a function to the Resolver interface.
type ResolverFunc func(ctx context.Context, creds Credentials) Principal

// Resolve implements Resolver.
func (f ResolverFunc) Resolve(ctx context.Context, creds Credentials) Principal { return f(ctx, creds) }

// HTTPMiddleware resolves the principal of every HTTP request and stores it in
// the request context. It never rejects a request: authorization happens later.
func HTTPMiddleware(r Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			p := r.Resolve(req.Context(), CredentialsFromHTTP(req))
			next.ServeHTTP(w, req.WithContext(WithPrincipal(req.Context(), p)))
		})
	}
}

// UnaryInterceptor is the gRPC counterpart of HTTPMiddleware.
func UnaryInterceptor(r Resolver) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(withResolvedPrincipal(ctx, r), req)
	}
}

// StreamInterceptor is the streaming counterpart of UnaryInterceptor.
func StreamInterceptor(r Resolver) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &principalStream{ServerStream: ss, ctx: withResolvedPrincipal(ss.Context(), r)})
	}
}

func withResolvedPrincipal(ctx context.Context, r Resolver) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	return WithPrincipal(ctx, r.Resolve(ctx, CredentialsFromMetadata(md)))
}

type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }
