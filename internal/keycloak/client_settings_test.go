package keycloak

import (
	"context"
	"io"
	"net/http"
	"testing"
)

func TestUpdateClientFieldsSetsURLsAndFlows(t *testing.T) {
	var putBody map[string]any
	m := &muxHandler{t: t, routes: map[string]func(http.ResponseWriter, *http.Request){
		"GET " + clientsBase + "/uuid-1": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"id":"uuid-1","clientId":"https://app","protocol":"openid-connect","implicitFlowEnabled":true}`)
		},
		"PUT " + clientsBase + "/uuid-1": func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			putBody = decodeJSONObject(t, body)
			w.WriteHeader(http.StatusNoContent)
		},
	}}
	c, _ := newTestClient(t, m)

	root, base := "https://app.example.com", "/home"
	on, off := true, false
	if err := c.UpdateClientFields(context.Background(), "uuid-1", ClientFields{
		RootURL:                   &root,
		BaseURL:                   &base,
		StandardFlowEnabled:       &on,
		DirectAccessGrantsEnabled: &off,
	}); err != nil {
		t.Fatalf("UpdateClientFields: %v", err)
	}
	want := map[string]any{
		"rootUrl":                   root,
		"baseUrl":                   base,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		// Unset fields keep their live values.
		"implicitFlowEnabled": true,
		"protocol":            "openid-connect",
	}
	for key, value := range want {
		if putBody[key] != value {
			t.Errorf("%s = %v, want %v", key, putBody[key], value)
		}
	}
}

func TestPostLogoutRedirectURIsRoundTrip(t *testing.T) {
	uris := []string{"https://app.example.com/", "https://app.example.com/signed-out"}
	joined := JoinPostLogoutRedirectURIs(uris)
	if joined != "https://app.example.com/##https://app.example.com/signed-out" {
		t.Errorf("joined = %q", joined)
	}
	got := SplitPostLogoutRedirectURIs(joined)
	if len(got) != 2 || got[0] != uris[0] || got[1] != uris[1] {
		t.Errorf("split = %v, want %v", got, uris)
	}
	if got := SplitPostLogoutRedirectURIs(""); got != nil {
		t.Errorf("split of an empty value = %v, want nil", got)
	}
}
