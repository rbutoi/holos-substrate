package keycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestServiceAccountRoleMappingCalls(t *testing.T) {
	var added, removed []RealmRole
	m := &muxHandler{t: t, routes: map[string]func(http.ResponseWriter, *http.Request){
		"GET " + clientsBase + "/uuid-1/service-account-user": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"id":"sa-user","username":"service-account-app"}`)
		},
		"GET " + realmBase + "/users/sa-user/role-mappings": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"realmMappings":[{"id":"r1","name":"default-roles-holos"}],`+
				`"clientMappings":{"realm-management":{"id":"rm-uuid","client":"realm-management","mappings":[{"id":"c1","name":"view-users"}]}}}`)
		},
		"POST " + realmBase + "/users/sa-user/role-mappings/realm": func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &added)
			w.WriteHeader(http.StatusNoContent)
		},
		"DELETE " + realmBase + "/users/sa-user/role-mappings/realm": func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &removed)
			w.WriteHeader(http.StatusNoContent)
		},
	}}
	c, _ := newTestClient(t, m)
	ctx := context.Background()

	user, err := c.GetServiceAccountUser(ctx, "uuid-1")
	if err != nil || user.ID != "sa-user" {
		t.Fatalf("GetServiceAccountUser = (%+v, %v), want user sa-user", user, err)
	}
	mappings, err := c.GetUserRoleMappings(ctx, "sa-user")
	if err != nil {
		t.Fatalf("GetUserRoleMappings: %v", err)
	}
	if len(mappings.RealmMappings) != 1 || mappings.RealmMappings[0].Name != "default-roles-holos" {
		t.Errorf("realm mappings = %+v", mappings.RealmMappings)
	}
	rm := mappings.ClientMappings["realm-management"]
	if rm.ID != "rm-uuid" || len(rm.Mappings) != 1 || rm.Mappings[0].Name != "view-users" {
		t.Errorf("realm-management mappings = %+v", rm)
	}

	if err := c.AddUserRealmRoles(ctx, "sa-user", []RealmRole{{ID: "r2", Name: "platform-reader"}}); err != nil {
		t.Fatalf("AddUserRealmRoles: %v", err)
	}
	if err := c.RemoveUserRealmRoles(ctx, "sa-user", []RealmRole{{ID: "r3", Name: "admin"}}); err != nil {
		t.Fatalf("RemoveUserRealmRoles: %v", err)
	}
	if len(added) != 1 || added[0].Name != "platform-reader" || len(removed) != 1 || removed[0].Name != "admin" {
		t.Errorf("added = %+v, removed = %+v", added, removed)
	}
}
