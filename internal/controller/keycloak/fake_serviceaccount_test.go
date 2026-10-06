package keycloak

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/holos-run/holos-substrate/internal/keycloak"
)

// The realm default role every fake service account keeps.
const (
	fakeDefaultRoleID   = "role-default"
	fakeDefaultRoleName = "default-roles-holos"
)

// fakeServiceAccounts models the realm roles that exist and, per
// service-account user, the realm and client roles mapped to it.
type fakeServiceAccounts struct {
	// realmRoles maps a realm role name to its UUID.
	realmRoles map[string]string
	// realmMappings maps a user ID to the realm role names it holds.
	realmMappings map[string]map[string]bool
	// clientMappings maps a user ID to, per client UUID, the role names it holds.
	clientMappings map[string]map[string]map[string]bool
}

func newFakeServiceAccounts() fakeServiceAccounts {
	return fakeServiceAccounts{
		realmRoles:     map[string]string{fakeDefaultRoleName: fakeDefaultRoleID},
		realmMappings:  map[string]map[string]bool{},
		clientMappings: map[string]map[string]map[string]bool{},
	}
}

// fakeServiceAccountUser is the ID of the service-account user of the client.
func fakeServiceAccountUser(clientUUID string) string {
	return "sa-" + clientUUID
}

// seedRealmRole registers a realm role so GetRealmRole resolves it.
func (f *fakeClient) seedRealmRole(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sa.realmRoles[name] = "realm-role-" + name
}

// serviceAccountRealmRoles returns the realm role names the client's service
// account holds, sorted.
func (f *fakeClient) serviceAccountRealmRoles(clientUUID string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.sa.realmMappings[fakeServiceAccountUser(clientUUID)]))
}

// serviceAccountClientRoles returns the role names the client's service account
// holds on targetUUID, sorted.
func (f *fakeClient) serviceAccountClientRoles(clientUUID, targetUUID string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.sa.clientMappings[fakeServiceAccountUser(clientUUID)][targetUUID]))
}

func (f *fakeClient) GetServiceAccountUser(ctx context.Context, clientUUID string) (*keycloak.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetServiceAccountUser:" + clientUUID)
	return &keycloak.User{ID: fakeServiceAccountUser(clientUUID)}, nil
}

func (f *fakeClient) GetUserRoleMappings(ctx context.Context, userID string) (*keycloak.UserRoleMappings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetUserRoleMappings:" + userID)
	out := &keycloak.UserRoleMappings{ClientMappings: map[string]keycloak.ClientRoleMappings{}}
	for _, name := range slices.Sorted(maps.Keys(f.sa.realmMappings[userID])) {
		out.RealmMappings = append(out.RealmMappings, keycloak.RealmRole{ID: f.sa.realmRoles[name], Name: name})
	}
	for clientUUID, roles := range f.sa.clientMappings[userID] {
		if len(roles) == 0 {
			continue
		}
		clientID, _ := f.clientIDForUUIDLocked(clientUUID)
		m := keycloak.ClientRoleMappings{ID: clientUUID, Client: clientID}
		for _, name := range slices.Sorted(maps.Keys(roles)) {
			m.Mappings = append(m.Mappings, keycloak.ClientRole{ID: f.clientRoles[clientUUID+"/"+name], Name: name, ContainerID: clientUUID})
		}
		out.ClientMappings[clientID] = m
	}
	return out, nil
}

func (f *fakeClient) GetRealmRole(ctx context.Context, roleName string) (*keycloak.RealmRole, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetRealmRole:" + roleName)
	id, ok := f.sa.realmRoles[roleName]
	if !ok {
		return nil, notFoundErr("/roles/" + roleName)
	}
	return &keycloak.RealmRole{ID: id, Name: roleName}, nil
}

func (f *fakeClient) AddUserRealmRoles(ctx context.Context, userID string, roles []keycloak.RealmRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("AddUserRealmRoles:" + userID + "/" + roleNames(roles))
	if f.sa.realmMappings[userID] == nil {
		f.sa.realmMappings[userID] = map[string]bool{}
	}
	for _, role := range roles {
		f.sa.realmMappings[userID][role.Name] = true
	}
	return nil
}

func (f *fakeClient) RemoveUserRealmRoles(ctx context.Context, userID string, roles []keycloak.RealmRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RemoveUserRealmRoles:" + userID + "/" + roleNames(roles))
	for _, role := range roles {
		delete(f.sa.realmMappings[userID], role.Name)
	}
	return nil
}

func (f *fakeClient) AddUserClientRoles(ctx context.Context, userID, clientUUID string, roles []keycloak.ClientRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("AddUserClientRoles:" + userID + "/" + clientUUID + "/" + roleNames(roles))
	if f.sa.clientMappings[userID] == nil {
		f.sa.clientMappings[userID] = map[string]map[string]bool{}
	}
	if f.sa.clientMappings[userID][clientUUID] == nil {
		f.sa.clientMappings[userID][clientUUID] = map[string]bool{}
	}
	for _, role := range roles {
		f.sa.clientMappings[userID][clientUUID][role.Name] = true
	}
	return nil
}

func (f *fakeClient) RemoveUserClientRoles(ctx context.Context, userID, clientUUID string, roles []keycloak.ClientRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RemoveUserClientRoles:" + userID + "/" + clientUUID + "/" + roleNames(roles))
	for _, role := range roles {
		delete(f.sa.clientMappings[userID][clientUUID], role.Name)
	}
	return nil
}

// roleNames lists the roles' names, sorted and comma-separated, for call records.
func roleNames(roles []keycloak.ClientRole) string {
	names := make([]string, 0, len(roles))
	for _, role := range roles {
		names = append(names, role.Name)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}
