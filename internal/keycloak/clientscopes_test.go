package keycloak

import (
	"context"
	"io"
	"net/http"
	"testing"
)

func TestClientScopeCalls(t *testing.T) {
	var put, deleted bool
	m := &muxHandler{t: t, routes: map[string]func(http.ResponseWriter, *http.Request){
		"GET " + realmBase + "/client-scopes": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `[{"id":"s1","name":"email"},{"id":"s2","name":"offline_access"}]`)
		},
		"GET " + clientsBase + "/uuid-1/default-client-scopes": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `[{"id":"s1","name":"email"}]`)
		},
		"PUT " + clientsBase + "/uuid-1/optional-client-scopes/s2": func(w http.ResponseWriter, _ *http.Request) {
			put = true
			w.WriteHeader(http.StatusNoContent)
		},
		"DELETE " + clientsBase + "/uuid-1/default-client-scopes/s1": func(w http.ResponseWriter, _ *http.Request) {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		},
	}}
	c, _ := newTestClient(t, m)
	ctx := context.Background()

	scopes, err := c.ListClientScopes(ctx)
	if err != nil || len(scopes) != 2 {
		t.Fatalf("ListClientScopes = (%v, %v), want two scopes", scopes, err)
	}
	attached, err := c.ListClientScopesOfKind(ctx, "uuid-1", DefaultClientScopes)
	if err != nil || len(attached) != 1 || attached[0].Name != "email" {
		t.Fatalf("ListClientScopesOfKind = (%v, %v), want [email]", attached, err)
	}
	if err := c.AddClientScope(ctx, "uuid-1", OptionalClientScopes, "s2"); err != nil {
		t.Fatalf("AddClientScope: %v", err)
	}
	if err := c.RemoveClientScope(ctx, "uuid-1", DefaultClientScopes, "s1"); err != nil {
		t.Fatalf("RemoveClientScope: %v", err)
	}
	if !put || !deleted {
		t.Errorf("put = %v, deleted = %v, want both", put, deleted)
	}
}
