package keycloak

import (
	"context"
	"net/http"
	"net/url"
)

// RealmRole is a realm role representation. It shares the role
// representation's shape with ClientRole; ClientRole is false for a realm role.
type RealmRole = ClientRole

// UserRoleMappings is the subset of a user's role-mapping representation the
// reconcilers read: the realm roles and, per client, the client roles the user
// holds directly.
type UserRoleMappings struct {
	// RealmMappings are the realm roles mapped to the user.
	RealmMappings []RealmRole `json:"realmMappings,omitempty"`
	// ClientMappings are the client roles mapped to the user, keyed by the
	// owning client's clientId.
	ClientMappings map[string]ClientRoleMappings `json:"clientMappings,omitempty"`
}

// ClientRoleMappings are the roles a user holds on one client.
type ClientRoleMappings struct {
	// ID is the owning client's UUID.
	ID string `json:"id,omitempty"`
	// Client is the owning client's clientId.
	Client string `json:"client,omitempty"`
	// Mappings are the client's roles mapped to the user.
	Mappings []ClientRole `json:"mappings,omitempty"`
}

// GetServiceAccountUser returns the user Keycloak creates for a client's
// service account via GET /admin/realms/{realm}/clients/{clientUUID}/service-account-user.
// A client without an enabled service account is returned as an *APIError.
func (c *Client) GetServiceAccountUser(ctx context.Context, clientUUID string) (*User, error) {
	path := c.adminPath("/clients/" + url.PathEscape(clientUUID) + "/service-account-user")
	user := &User{}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, user); err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserRoleMappings returns the realm and client roles mapped directly to the
// user via GET /admin/realms/{realm}/users/{userId}/role-mappings.
func (c *Client) GetUserRoleMappings(ctx context.Context, userID string) (*UserRoleMappings, error) {
	path := c.adminPath("/users/" + url.PathEscape(userID) + "/role-mappings")
	mappings := &UserRoleMappings{}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, mappings); err != nil {
		return nil, err
	}
	return mappings, nil
}

// GetRealmRole returns the realm role named roleName via
// GET /admin/realms/{realm}/roles/{roleName}. A missing role is returned as an
// *APIError reporting IsNotFound.
func (c *Client) GetRealmRole(ctx context.Context, roleName string) (*RealmRole, error) {
	path := c.adminPath("/roles/" + url.PathEscape(roleName))
	role := &RealmRole{}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, role); err != nil {
		return nil, err
	}
	return role, nil
}

// AddUserRealmRoles maps the realm roles to the user via
// POST /admin/realms/{realm}/users/{userId}/role-mappings/realm. Each role must
// carry its ID and Name. Mapping a role the user already holds is a no-op.
func (c *Client) AddUserRealmRoles(ctx context.Context, userID string, roles []RealmRole) error {
	path := c.adminPath("/users/" + url.PathEscape(userID) + "/role-mappings/realm")
	return c.doJSON(ctx, http.MethodPost, path, roles, nil)
}

// RemoveUserRealmRoles unmaps the realm roles from the user via
// DELETE /admin/realms/{realm}/users/{userId}/role-mappings/realm. Each role
// must carry its ID and Name.
func (c *Client) RemoveUserRealmRoles(ctx context.Context, userID string, roles []RealmRole) error {
	path := c.adminPath("/users/" + url.PathEscape(userID) + "/role-mappings/realm")
	return c.doJSON(ctx, http.MethodDelete, path, roles, nil)
}

// AddUserClientRoles maps the client's roles to the user via
// POST /admin/realms/{realm}/users/{userId}/role-mappings/clients/{clientUUID}.
// Each role must carry its ID and Name. Mapping a role the user already holds is
// a no-op.
func (c *Client) AddUserClientRoles(ctx context.Context, userID, clientUUID string, roles []ClientRole) error {
	path := c.adminPath("/users/" + url.PathEscape(userID) + "/role-mappings/clients/" + url.PathEscape(clientUUID))
	return c.doJSON(ctx, http.MethodPost, path, roles, nil)
}

// RemoveUserClientRoles unmaps the client's roles from the user via
// DELETE /admin/realms/{realm}/users/{userId}/role-mappings/clients/{clientUUID}.
// Each role must carry its ID and Name.
func (c *Client) RemoveUserClientRoles(ctx context.Context, userID, clientUUID string, roles []ClientRole) error {
	path := c.adminPath("/users/" + url.PathEscape(userID) + "/role-mappings/clients/" + url.PathEscape(clientUUID))
	return c.doJSON(ctx, http.MethodDelete, path, roles, nil)
}
