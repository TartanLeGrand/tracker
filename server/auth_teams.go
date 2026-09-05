package server

import (
	"context"

	authv1 "github.com/bananaops/tracker/generated/proto/auth/v1alpha1"
	"github.com/bananaops/tracker/internal/auth/authz"
)

func (a *Auth) ListTeams(ctx context.Context, _ *authv1.ListTeamsRequest) (*authv1.ListTeamsResponse, error) {
	if err := authz.Authorize(ctx); err != nil {
		return nil, err
	}
	teams, err := a.teams.List(ctx)
	if err != nil {
		return nil, storeError(err, "teams")
	}
	resp := &authv1.ListTeamsResponse{Teams: make([]*authv1.Team, 0, len(teams))}
	for _, t := range teams {
		resp.Teams = append(resp.Teams, toProtoTeam(t))
	}
	return resp, nil
}
