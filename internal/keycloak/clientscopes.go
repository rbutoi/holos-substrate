package keycloak

import (
	"context"
	"net/http"
	"net/url"
)

// ClientScope is the subset of a client-scope representation the reconcilers
// read: its UUID and its name.
type ClientScope struct {
	// ID is the client scope's UUID.
	ID string `json:"id,omitempty"`
	// Name is the client scope's name, e.g. offline_access.
	Name string `json:"name,omitempty"`
}

// ClientScopeKind is how a client scope is attached to a client: a default
// scope is added to every token the client requests, and an optional scope only
// when the client asks for it.
type ClientScopeKind string

const (
	// DefaultClientScopes attaches a scope to every token the client requests.
	DefaultClientScopes ClientScopeKind = "default-client-scopes"
	// OptionalClientScopes attaches a scope only when the client requests it.
	OptionalClientScopes ClientScopeKind = "optional-client-scopes"
)

// ListClientScopes returns the realm's client scopes via
// GET /admin/realms/{realm}/client-scopes, to resolve a scope name to its UUID.
func (c *Client) ListClientScopes(ctx context.Context) ([]ClientScope, error) {
	var scopes []ClientScope
	if err := c.doJSON(ctx, http.MethodGet, c.adminPath("/client-scopes"), nil, &scopes); err != nil {
		return nil, err
	}
	return scopes, nil
}

// ListClientScopesOfKind returns the scopes attached to the client as kind via
// GET /admin/realms/{realm}/clients/{clientUUID}/{kind}.
func (c *Client) ListClientScopesOfKind(ctx context.Context, clientUUID string, kind ClientScopeKind) ([]ClientScope, error) {
	path := c.adminPath("/clients/" + url.PathEscape(clientUUID) + "/" + string(kind))
	var scopes []ClientScope
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &scopes); err != nil {
		return nil, err
	}
	return scopes, nil
}

// AddClientScope attaches the scope to the client as kind via
// PUT /admin/realms/{realm}/clients/{clientUUID}/{kind}/{scopeID}.
func (c *Client) AddClientScope(ctx context.Context, clientUUID string, kind ClientScopeKind, scopeID string) error {
	path := c.adminPath("/clients/" + url.PathEscape(clientUUID) + "/" + string(kind) + "/" + url.PathEscape(scopeID))
	return c.doJSON(ctx, http.MethodPut, path, nil, nil)
}

// RemoveClientScope detaches the scope of kind from the client via
// DELETE /admin/realms/{realm}/clients/{clientUUID}/{kind}/{scopeID}.
func (c *Client) RemoveClientScope(ctx context.Context, clientUUID string, kind ClientScopeKind, scopeID string) error {
	path := c.adminPath("/clients/" + url.PathEscape(clientUUID) + "/" + string(kind) + "/" + url.PathEscape(scopeID))
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil)
}
