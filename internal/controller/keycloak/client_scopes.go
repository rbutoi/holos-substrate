package keycloak

import (
	"context"
	"fmt"

	keycloakv1alpha1 "github.com/holos-run/holos-substrate/api/keycloak/v1alpha1"
	"github.com/holos-run/holos-substrate/internal/keycloak"
)

// managedClientScopes is one kind of client scope the spec manages and the
// scope names it wants attached.
type managedClientScopes struct {
	kind keycloak.ClientScopeKind
	want []string
}

// ensureClientScopes makes the client's default and optional scopes exactly the
// spec's, for each list the spec sets. It removes before it adds, so a scope can
// move between the two in one reconcile, and reports whether it changed
// anything. existing is the client as found, or nil for one just created; when
// its scopes already match, nothing is listed or changed.
func (r *ClientReconciler) ensureClientScopes(ctx context.Context, kc ClientClient, kclient *keycloakv1alpha1.Client, clientUUID string, existing *keycloak.OIDCClient) (bool, error) {
	var managed []managedClientScopes
	if kclient.Spec.DefaultClientScopes != nil {
		managed = append(managed, managedClientScopes{keycloak.DefaultClientScopes, kclient.Spec.DefaultClientScopes})
	}
	if kclient.Spec.OptionalClientScopes != nil {
		managed = append(managed, managedClientScopes{keycloak.OptionalClientScopes, kclient.Spec.OptionalClientScopes})
	}
	if existing != nil {
		live := map[keycloak.ClientScopeKind][]string{
			keycloak.DefaultClientScopes:  existing.DefaultClientScopes,
			keycloak.OptionalClientScopes: existing.OptionalClientScopes,
		}
		inSync := true
		for _, m := range managed {
			inSync = inSync && sameStringSet(live[m.kind], m.want)
		}
		if inSync {
			return false, nil
		}
	}

	type plan struct {
		kind    keycloak.ClientScopeKind
		missing []string
		extra   []keycloak.ClientScope
	}
	var plans []plan
	for _, m := range managed {
		current, err := kc.ListClientScopesOfKind(ctx, clientUUID, m.kind)
		recordKeycloakAPI(opListClientScopes, err)
		if err != nil {
			return false, fmt.Errorf("listing %s of Keycloak client %q: %w", m.kind, kclient.Spec.ClientID, err)
		}
		missing, extra := planSet(m.want, current, func(s keycloak.ClientScope) string { return s.Name })
		plans = append(plans, plan{m.kind, missing, extra})
	}

	changed := false
	for _, p := range plans {
		for _, scope := range p.extra {
			err := kc.RemoveClientScope(ctx, clientUUID, p.kind, scope.ID)
			recordKeycloakAPI(opRemoveClientScope, err)
			if err != nil {
				return changed, fmt.Errorf("removing %s %q from Keycloak client %q: %w", p.kind, scope.Name, kclient.Spec.ClientID, err)
			}
			changed = true
		}
	}

	var ids map[string]string
	for _, p := range plans {
		for _, name := range p.missing {
			if ids == nil {
				scopes, err := kc.ListClientScopes(ctx)
				recordKeycloakAPI(opListClientScopes, err)
				if err != nil {
					return changed, fmt.Errorf("listing the realm's client scopes: %w", err)
				}
				ids = make(map[string]string, len(scopes))
				for _, scope := range scopes {
					ids[scope.Name] = scope.ID
				}
			}
			id, ok := ids[name]
			if !ok {
				return changed, fmt.Errorf("client scope %q, declared for Keycloak client %q, does not exist", name, kclient.Spec.ClientID)
			}
			err := kc.AddClientScope(ctx, clientUUID, p.kind, id)
			recordKeycloakAPI(opAddClientScope, err)
			if err != nil {
				return changed, fmt.Errorf("adding %s %q to Keycloak client %q: %w", p.kind, name, kclient.Spec.ClientID, err)
			}
			changed = true
		}
	}
	return changed, nil
}
