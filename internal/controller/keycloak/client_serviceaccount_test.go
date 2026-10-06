package keycloak

import (
	"context"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	keycloakv1alpha1 "github.com/holos-run/holos-substrate/api/keycloak/v1alpha1"
	"github.com/holos-run/holos-substrate/internal/keycloak"
)

// serviceAccountSpec makes the spec a confidential client with a service
// account holding the given roles.
func serviceAccountSpec(sa *keycloakv1alpha1.ClientServiceAccount) func(*keycloakv1alpha1.ClientSpec) {
	return func(s *keycloakv1alpha1.ClientSpec) {
		s.Type = keycloakv1alpha1.ClientTypeConfidential
		s.SecretRef = &keycloakv1alpha1.ClientSecretReference{Name: "app-oidc", Key: "client_secret"}
		s.ServiceAccount = sa
	}
}

func TestClientReconcileServiceAccountRoles(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-service-account"
	key := newSettingsClient(t, ctx, ns, serviceAccountSpec(&keycloakv1alpha1.ClientServiceAccount{
		RealmRoles:  []string{"platform-reader"},
		ClientRoles: []keycloakv1alpha1.ServiceAccountClientRole{{ClientID: "realm-management", Role: "manage-clients"}},
	}))

	fake := newFakeClient()
	fake.seedRealmRole("platform-reader")
	fake.seedRealmRole("admin")
	fake.seedClient("realm-management", "rm-uuid")
	fake.seedClientRole("rm-uuid", "manage-clients", "role-manage-clients")
	fake.seedClientRole("rm-uuid", "manage-users", "role-manage-users")
	r, _ := newClientReconciler(fake, ns)
	reconcileClientToSteady(t, ctx, r, key)

	uuid := fake.clients[settingsClientID(ns)]
	if !ptr.Deref(fake.clientObject(uuid).ServiceAccountsEnabled, false) {
		t.Errorf("service account was not enabled")
	}
	wantRealm := []string{fakeDefaultRoleName, "platform-reader"}
	if got := fake.serviceAccountRealmRoles(uuid); !slices.Equal(got, wantRealm) {
		t.Errorf("realm roles = %v, want %v", got, wantRealm)
	}
	if got := fake.serviceAccountClientRoles(uuid, "rm-uuid"); !slices.Equal(got, []string{"manage-clients"}) {
		t.Errorf("realm-management roles = %v, want [manage-clients]", got)
	}

	// Roles granted in the console are removed, a declared role removed in the
	// console is put back, and the realm's default role is kept.
	user := fakeServiceAccountUser(uuid)
	if err := fake.AddUserRealmRoles(ctx, user, []keycloak.RealmRole{{Name: "admin"}}); err != nil {
		t.Fatalf("seeding drift: %v", err)
	}
	if err := fake.RemoveUserClientRoles(ctx, user, "rm-uuid", []keycloak.ClientRole{{Name: "manage-clients"}}); err != nil {
		t.Fatalf("seeding drift: %v", err)
	}
	if err := fake.AddUserClientRoles(ctx, user, "rm-uuid", []keycloak.ClientRole{{Name: "manage-users"}}); err != nil {
		t.Fatalf("seeding drift: %v", err)
	}
	if _, err := reconcileClient(ctx, r, key); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := fake.serviceAccountRealmRoles(uuid); !slices.Equal(got, wantRealm) {
		t.Errorf("realm roles after drift = %v, want %v", got, wantRealm)
	}
	if got := fake.serviceAccountClientRoles(uuid, "rm-uuid"); !slices.Equal(got, []string{"manage-clients"}) {
		t.Errorf("realm-management roles after drift = %v, want [manage-clients]", got)
	}
	got := getKClient(t, ctx, key)
	if got.Status.LastMutationReason == "" {
		t.Errorf("a role change was not stamped as a mutation")
	}
}

func TestClientReconcileStampsMutationBeforeLaterFailure(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-service-account-partial"
	key := newSettingsClient(t, ctx, ns, serviceAccountSpec(&keycloakv1alpha1.ClientServiceAccount{
		RealmRoles:  []string{"platform-reader"},
		ClientRoles: []keycloakv1alpha1.ServiceAccountClientRole{{ClientID: "does-not-exist", Role: "admin"}},
	}))

	fake := newFakeClient()
	fake.seedRealmRole("platform-reader")
	r, _ := newClientReconciler(fake, ns)
	_, _ = reconcileClient(ctx, r, key)
	if _, err := reconcileClient(ctx, r, key); err == nil {
		t.Fatalf("reconcile succeeded with a client role on a client that does not exist")
	}

	// The realm roles were granted before the client role failed, and that
	// change is recorded.
	uuid := fake.clients[settingsClientID(ns)]
	if got := fake.serviceAccountRealmRoles(uuid); !slices.Contains(got, "platform-reader") {
		t.Fatalf("realm roles = %v, want platform-reader granted", got)
	}
	if got := getKClient(t, ctx, key); got.Status.LastMutatedTime == nil {
		t.Errorf("the realm role change before the failure was not stamped")
	}
}

func TestClientReconcileServiceAccountMissingRoleFails(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-service-account-missing"
	key := newSettingsClient(t, ctx, ns, serviceAccountSpec(&keycloakv1alpha1.ClientServiceAccount{
		RealmRoles: []string{"does-not-exist"},
	}))

	fake := newFakeClient()
	r, _ := newClientReconciler(fake, ns)
	_, _ = reconcileClient(ctx, r, key)
	_, _ = reconcileClient(ctx, r, key)

	got := getKClient(t, ctx, key)
	if status, _, ok := conditionStatus(got.Status.Conditions, ConditionReady); ok && status == metav1.ConditionTrue {
		t.Errorf("Ready = True with a service account role that does not exist")
	}
}
