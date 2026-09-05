package server

import (
	"context"

	authv1 "github.com/bananaops/tracker/generated/proto/auth/v1alpha1"
	"github.com/bananaops/tracker/internal/auth/authz"
)

func (a *Auth) ListApiKeys(ctx context.Context, _ *authv1.ListApiKeysRequest) (*authv1.ListApiKeysResponse, error) {
	if err := authz.Authorize(ctx); err != nil {
		return nil, err
	}
	keys, err := a.keys.List(ctx)
	if err != nil {
		return nil, storeError(err, "api keys")
	}
	resp := &authv1.ListApiKeysResponse{ApiKeys: make([]*authv1.ApiKey, 0, len(keys))}
	for _, k := range keys {
		resp.ApiKeys = append(resp.ApiKeys, toProtoAPIKey(k))
	}
	return resp, nil
}
