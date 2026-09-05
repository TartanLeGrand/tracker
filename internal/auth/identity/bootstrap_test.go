package identity

import (
	"context"
	"testing"

	"github.com/bananaops/tracker/internal/auth"
	store "github.com/bananaops/tracker/internal/stores"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type memUsers struct{ users []*store.User }

func (m *memUsers) Count(context.Context) (int64, error) { return int64(len(m.users)), nil }
func (m *memUsers) Create(_ context.Context, u *store.User) error {
	u.ID = primitive.NewObjectID()
	m.users = append(m.users, u)
	return nil
}

type memTeams struct{ teams map[string]*store.Team }

func (m *memTeams) GetByName(_ context.Context, name string) (*store.Team, error) {
	if t, ok := m.teams[name]; ok {
		return t, nil
	}
	return nil, store.ErrNotFound
}
func (m *memTeams) Create(_ context.Context, t *store.Team) error {
	t.ID = primitive.NewObjectID()
	m.teams[t.Name] = t
	return nil
}

func TestBootstrapCreatesAdminWithGivenPassword(t *testing.T) {
	users, teams := &memUsers{}, &memTeams{teams: map[string]*store.Team{}}
	res, err := Bootstrap(context.Background(), users, teams, "initial-admin-password")
	require.NoError(t, err)
	assert.True(t, res.AdminCreated)
	assert.Empty(t, res.GeneratedPassword)

	admins := teams.teams[store.AdministratorsTeamName]
	require.NotNil(t, admins)
	assert.True(t, admins.Builtin)
	assert.True(t, admins.Scope.All)
	assert.Len(t, admins.Permissions, len(auth.AllPermissions()))
	assert.Equal(t, admins.ID, res.AdminsTeamID)

	require.Len(t, users.users, 1)
	admin := users.users[0]
	assert.Equal(t, "admin", admin.Username)
	assert.Equal(t, store.UserSourceLocal, admin.Source)
	assert.True(t, admin.MustChangePassword)
	assert.Equal(t, []primitive.ObjectID{admins.ID}, admin.Teams)
	ok, _ := auth.VerifyPassword(admin.PasswordHash, "initial-admin-password")
	assert.True(t, ok)
}

func TestBootstrapGeneratesPasswordAndIsIdempotent(t *testing.T) {
	users, teams := &memUsers{}, &memTeams{teams: map[string]*store.Team{}}
	res, err := Bootstrap(context.Background(), users, teams, "")
	require.NoError(t, err)
	assert.Len(t, res.GeneratedPassword, 24)
	ok, _ := auth.VerifyPassword(users.users[0].PasswordHash, res.GeneratedPassword)
	assert.True(t, ok)

	again, err := Bootstrap(context.Background(), users, teams, "")
	require.NoError(t, err)
	assert.False(t, again.AdminCreated)
	assert.Len(t, users.users, 1)
	assert.Len(t, teams.teams, 1)
}
