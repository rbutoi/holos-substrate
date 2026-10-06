package keycloak

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	keycloakv1alpha1 "github.com/holos-run/holos-substrate/api/keycloak/v1alpha1"
	"github.com/holos-run/holos-substrate/internal/keycloak"
)

// settingsClientID is the clientId newSettingsClient gives the Client in ns.
func settingsClientID(ns string) string {
	return "https://" + ns + ".holos.internal"
}

// newSettingsClient creates a Client CR in a fresh namespace with a ready
// Instance, applying edit to its spec, and returns its key.
func newSettingsClient(t *testing.T, ctx context.Context, ns string, edit func(*keycloakv1alpha1.ClientSpec)) client.ObjectKey {
	t.Helper()
	makeNamespace(t, ctx, ns)
	createIgnoreExists(t, ctx, newCredentialSecret(ns, keycloakv1alpha1.DefaultCredentialsSecretName))
	readyInstance(t, ctx, ns, "kc")
	kclient := &keycloakv1alpha1.Client{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "app"},
		Spec: keycloakv1alpha1.ClientSpec{
			ClientID:    settingsClientID(ns),
			Type:        keycloakv1alpha1.ClientTypePublic,
			InstanceRef: keycloakv1alpha1.InstanceReference{Name: "kc"},
		},
	}
	edit(&kclient.Spec)
	if err := shared.k8sClient.Create(ctx, kclient); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return client.ObjectKeyFromObject(kclient)
}

func TestClientReconcileDisplayNameAndURLsOnCreate(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned (KUBEBUILDER_ASSETS unset); run via make controller-test")
	}
	ctx := context.Background()
	const ns = "kc-client-urls-create"
	key := newSettingsClient(t, ctx, ns, func(s *keycloakv1alpha1.ClientSpec) {
		s.DisplayName = ptr.To("My App")
		s.RootURL = ptr.To("https://app.example.com")
		s.BaseURL = ptr.To("/home")
	})

	fake := newFakeClient()
	r, _ := newClientReconciler(fake, ns)
	reconcileClientToSteady(t, ctx, r, key)

	got := fake.clientObject(fake.clients[settingsClientID(ns)])
	if got.Name != "My App" || got.RootURL != "https://app.example.com" || got.BaseURL != "/home" {
		t.Errorf("created client (name, rootUrl, baseUrl) = (%q, %q, %q), want (%q, %q, %q)",
			got.Name, got.RootURL, got.BaseURL, "My App", "https://app.example.com", "/home")
	}
}

func TestClientReconcileNameDefaultsToObjectName(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-name-default"
	key := newSettingsClient(t, ctx, ns, func(*keycloakv1alpha1.ClientSpec) {})

	fake := newFakeClient()
	r, _ := newClientReconciler(fake, ns)
	reconcileClientToSteady(t, ctx, r, key)

	if got := fake.clientObject(fake.clients[settingsClientID(ns)]).Name; got != "app" {
		t.Errorf("created client name = %q, want the object name %q", got, "app")
	}
}

func TestClientReconcileDisplayNameAndURLsDriftCorrected(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-urls-drift"
	key := newSettingsClient(t, ctx, ns, func(s *keycloakv1alpha1.ClientSpec) {
		s.Adopt = true
		s.DisplayName = ptr.To("My App")
		s.RootURL = ptr.To("https://app.example.com")
		s.BaseURL = ptr.To("/home")
	})

	fake := newFakeClient()
	fake.seedClient(settingsClientID(ns), "drift-uuid")
	fake.editClient("drift-uuid", func(c *keycloak.OIDCClient) {
		c.Name = "renamed in console"
		c.RootURL = "https://wrong.example.com"
		c.BaseURL = "/elsewhere"
	})
	r, _ := newClientReconciler(fake, ns)
	reconcileClientToSteady(t, ctx, r, key)

	got := fake.clientObject("drift-uuid")
	if got.Name != "My App" || got.RootURL != "https://app.example.com" || got.BaseURL != "/home" {
		t.Errorf("after reconcile (name, rootUrl, baseUrl) = (%q, %q, %q), want the spec values", got.Name, got.RootURL, got.BaseURL)
	}
}

func TestClientReconcileOmittedNameAndURLsLeftAlone(t *testing.T) {
	if shared == nil {
		t.Skip("envtest not provisioned")
	}
	ctx := context.Background()
	const ns = "kc-client-urls-omitted"
	key := newSettingsClient(t, ctx, ns, func(s *keycloakv1alpha1.ClientSpec) {
		s.Adopt = true
	})

	fake := newFakeClient()
	fake.seedClient(settingsClientID(ns), "omitted-uuid")
	fake.editClient("omitted-uuid", func(c *keycloak.OIDCClient) {
		c.Enabled = true
		c.PublicClient = true
		c.Attributes = map[string]string{keycloak.PKCECodeChallengeMethodAttr: keycloak.PKCEMethodS256}
		c.Name = "set in console"
		c.RootURL = "https://console.example.com"
		c.BaseURL = "/console"
	})
	r, _ := newClientReconciler(fake, ns)
	reconcileClientToSteady(t, ctx, r, key)

	got := fake.clientObject("omitted-uuid")
	if got.Name != "set in console" || got.RootURL != "https://console.example.com" || got.BaseURL != "/console" {
		t.Errorf("after reconcile (name, rootUrl, baseUrl) = (%q, %q, %q), want the console values left alone", got.Name, got.RootURL, got.BaseURL)
	}
	if fake.callsContain("UpdateClient:omitted-uuid") {
		t.Errorf("an omitted field triggered an update; calls = %v", fake.calls)
	}
}
