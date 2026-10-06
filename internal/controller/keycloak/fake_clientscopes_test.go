package keycloak

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/holos-run/holos-substrate/internal/keycloak"
)

// fakeClientScopes models the realm's client scopes and, per client UUID and
// kind, the scope names attached to it. A scope's ID is fakeClientScopeID of its
// name.
type fakeClientScopes struct {
	// names is the set of client scopes that exist in the realm.
	names map[string]bool
	// attached maps a client UUID to, per kind, the attached scope names.
	attached map[string]map[keycloak.ClientScopeKind]map[string]bool
}

func newFakeClientScopes() fakeClientScopes {
	return fakeClientScopes{
		names:    map[string]bool{},
		attached: map[string]map[keycloak.ClientScopeKind]map[string]bool{},
	}
}

// fakeClientScopeID is the ID of the client scope named name.
func fakeClientScopeID(name string) string {
	return "scope-" + name
}

// attachedLocked returns the scope names attached to the client as kind, sorted.
// The caller holds the fake's lock.
func (s *fakeClientScopes) attachedLocked(clientUUID string, kind keycloak.ClientScopeKind) []string {
	return slices.Sorted(maps.Keys(s.attached[clientUUID][kind]))
}

// seedClientScope registers a realm client scope so it resolves by name.
func (f *fakeClient) seedClientScope(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes.names[name] = true
}

// attachedClientScopes returns the scope names attached to the client as kind,
// sorted.
func (f *fakeClient) attachedClientScopes(clientUUID string, kind keycloak.ClientScopeKind) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scopes.attachedLocked(clientUUID, kind)
}

func (f *fakeClient) ListClientScopes(ctx context.Context) ([]keycloak.ClientScope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListClientScopes")
	out := []keycloak.ClientScope{}
	for _, name := range slices.Sorted(maps.Keys(f.scopes.names)) {
		out = append(out, keycloak.ClientScope{ID: fakeClientScopeID(name), Name: name})
	}
	return out, nil
}

func (f *fakeClient) ListClientScopesOfKind(ctx context.Context, clientUUID string, kind keycloak.ClientScopeKind) ([]keycloak.ClientScope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListClientScopesOfKind:" + clientUUID + "/" + string(kind))
	out := []keycloak.ClientScope{}
	for _, name := range f.scopes.attachedLocked(clientUUID, kind) {
		out = append(out, keycloak.ClientScope{ID: fakeClientScopeID(name), Name: name})
	}
	return out, nil
}

func (f *fakeClient) AddClientScope(ctx context.Context, clientUUID string, kind keycloak.ClientScopeKind, scopeID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("AddClientScope:" + clientUUID + "/" + string(kind) + "/" + scopeID)
	if f.scopes.attached[clientUUID] == nil {
		f.scopes.attached[clientUUID] = map[keycloak.ClientScopeKind]map[string]bool{}
	}
	if f.scopes.attached[clientUUID][kind] == nil {
		f.scopes.attached[clientUUID][kind] = map[string]bool{}
	}
	f.scopes.attached[clientUUID][kind][strings.TrimPrefix(scopeID, "scope-")] = true
	return nil
}

func (f *fakeClient) RemoveClientScope(ctx context.Context, clientUUID string, kind keycloak.ClientScopeKind, scopeID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("RemoveClientScope:" + clientUUID + "/" + string(kind) + "/" + scopeID)
	delete(f.scopes.attached[clientUUID][kind], strings.TrimPrefix(scopeID, "scope-"))
	return nil
}
