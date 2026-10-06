package keycloak

import (
	"context"
	"slices"
	"strings"
	"testing"

	keycloakv1alpha1 "github.com/holos-run/holos-substrate/api/keycloak/v1alpha1"
	"github.com/holos-run/holos-substrate/internal/keycloak"
)

func TestClientReconcileClientScopes(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-scopes"
	key := newSettingsClient(t, ctx, ns, func(s *keycloakv1alpha1.ClientSpec) {
		s.DefaultClientScopes = []string{"email", "profile"}
		s.OptionalClientScopes = []string{"offline_access"}
	})

	fake := newFakeClient()
	for _, name := range []string{"email", "profile", "offline_access", "roles", "phone"} {
		fake.seedClientScope(name)
	}
	r, _ := newClientReconciler(fake, ns)
	reconcileClientToSteady(t, ctx, r, key)

	uuid := fake.clients[settingsClientID(ns)]
	if got := fake.attachedClientScopes(uuid, keycloak.DefaultClientScopes); !slices.Equal(got, []string{"email", "profile"}) {
		t.Errorf("default scopes = %v, want [email profile]", got)
	}
	if got := fake.attachedClientScopes(uuid, keycloak.OptionalClientScopes); !slices.Equal(got, []string{"offline_access"}) {
		t.Errorf("optional scopes = %v, want [offline_access]", got)
	}

	// In sync, a reconcile makes no client-scope calls at all.
	fake.resetCalls()
	if _, err := reconcileClient(ctx, r, key); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "ClientScope") {
			t.Errorf("an in-sync reconcile made a client-scope call: %s", call)
		}
	}

	// Scopes added in the console, or by the realm's defaults, are removed.
	_ = fake.AddClientScope(ctx, uuid, keycloak.DefaultClientScopes, fakeClientScopeID("roles"))
	_ = fake.AddClientScope(ctx, uuid, keycloak.OptionalClientScopes, fakeClientScopeID("phone"))
	if _, err := reconcileClient(ctx, r, key); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := fake.attachedClientScopes(uuid, keycloak.DefaultClientScopes); !slices.Equal(got, []string{"email", "profile"}) {
		t.Errorf("default scopes after drift = %v, want [email profile]", got)
	}
	if got := fake.attachedClientScopes(uuid, keycloak.OptionalClientScopes); !slices.Equal(got, []string{"offline_access"}) {
		t.Errorf("optional scopes after drift = %v, want [offline_access]", got)
	}
}

func TestClientReconcileOmittedClientScopesLeftAlone(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-scopes-omitted"
	key := newSettingsClient(t, ctx, ns, func(s *keycloakv1alpha1.ClientSpec) {
		s.OptionalClientScopes = []string{"offline_access"}
	})

	fake := newFakeClient()
	fake.seedClientScope("offline_access")
	fake.seedClientScope("roles")
	r, _ := newClientReconciler(fake, ns)
	reconcileClientToSteady(t, ctx, r, key)

	uuid := fake.clients[settingsClientID(ns)]
	_ = fake.AddClientScope(ctx, uuid, keycloak.DefaultClientScopes, fakeClientScopeID("roles"))
	if _, err := reconcileClient(ctx, r, key); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := fake.attachedClientScopes(uuid, keycloak.DefaultClientScopes); !slices.Equal(got, []string{"roles"}) {
		t.Errorf("default scopes = %v, want the unmanaged [roles] left alone", got)
	}
}
