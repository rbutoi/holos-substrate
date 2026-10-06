package keycloak

import (
	"context"
	"fmt"
	"maps"
	"slices"

	keycloakv1alpha1 "github.com/holos-run/holos-substrate/api/keycloak/v1alpha1"
	"github.com/holos-run/holos-substrate/internal/keycloak"
)

// ensureServiceAccountRoles makes the client's service account hold exactly the
// roles the spec lists, plus the realm's default role, which Keycloak grants
// every user. It does nothing when the spec omits serviceAccount. It reports
// whether it changed any role mapping.
func (r *ClientReconciler) ensureServiceAccountRoles(ctx context.Context, kc ClientClient, kclient *keycloakv1alpha1.Client, clientUUID string) (bool, error) {
	sa := kclient.Spec.ServiceAccount
	if sa == nil {
		return false, nil
	}

	user, err := kc.GetServiceAccountUser(ctx, clientUUID)
	recordKeycloakAPI(opGetServiceAccountUser, err)
	if err != nil {
		return false, fmt.Errorf("getting the service account of Keycloak client %q: %w", kclient.Spec.ClientID, err)
	}
	defaultRole, err := r.realmDefaultRole(ctx, kc, kclient)
	if err != nil {
		return false, err
	}
	current, err := kc.GetUserRoleMappings(ctx, user.ID)
	recordKeycloakAPI(opGetUserRoleMappings, err)
	if err != nil {
		return false, fmt.Errorf("getting the roles of Keycloak client %q's service account: %w", kclient.Spec.ClientID, err)
	}

	wantRealm := sa.RealmRoles
	if defaultRole != "" {
		wantRealm = append(slices.Clone(wantRealm), defaultRole)
	}
	changed, err := convergeRoles(wantRealm, current.RealmMappings,
		func(name string) (*keycloak.ClientRole, error) {
			role, err := kc.GetRealmRole(ctx, name)
			recordKeycloakAPI(opGetRealmRole, ignoreNotFound(err))
			if err != nil {
				return nil, fmt.Errorf("resolving realm role %q: %w", name, err)
			}
			return role, nil
		},
		func(roles []keycloak.ClientRole) error {
			err := kc.AddUserRealmRoles(ctx, user.ID, roles)
			recordKeycloakAPI(opAddUserRealmRoles, err)
			return err
		},
		func(roles []keycloak.ClientRole) error {
			err := kc.RemoveUserRealmRoles(ctx, user.ID, roles)
			recordKeycloakAPI(opRemoveUserRealmRoles, err)
			return err
		})
	if err != nil {
		return changed, fmt.Errorf("converging the realm roles of Keycloak client %q's service account: %w", kclient.Spec.ClientID, err)
	}

	wantClient := map[string][]string{}
	for _, role := range sa.ClientRoles {
		wantClient[role.ClientID] = append(wantClient[role.ClientID], role.Role)
	}
	clientIDs := map[string]bool{}
	for clientID := range wantClient {
		clientIDs[clientID] = true
	}
	for clientID := range current.ClientMappings {
		clientIDs[clientID] = true
	}
	for _, clientID := range slices.Sorted(maps.Keys(clientIDs)) {
		held := current.ClientMappings[clientID]
		targetUUID := held.ID
		resolveTarget := func() error {
			if targetUUID != "" {
				return nil
			}
			target, err := kc.FindClientByClientID(ctx, clientID)
			recordKeycloakAPI(opFindClientByClientID, err)
			if err != nil {
				return fmt.Errorf("finding Keycloak client %q: %w", clientID, err)
			}
			if target == nil {
				return fmt.Errorf("client %q, which defines a service account role, does not exist in Keycloak", clientID)
			}
			targetUUID = target.ID
			return nil
		}
		clientChanged, err := convergeRoles(wantClient[clientID], held.Mappings,
			func(name string) (*keycloak.ClientRole, error) {
				if err := resolveTarget(); err != nil {
					return nil, err
				}
				role, err := kc.GetClientRole(ctx, targetUUID, name)
				recordKeycloakAPI(opGetClientRole, ignoreNotFound(err))
				if err != nil {
					return nil, fmt.Errorf("resolving client role %q: %w", name, err)
				}
				return role, nil
			},
			func(roles []keycloak.ClientRole) error {
				err := kc.AddUserClientRoles(ctx, user.ID, targetUUID, roles)
				recordKeycloakAPI(opAddUserClientRoles, err)
				return err
			},
			func(roles []keycloak.ClientRole) error {
				err := kc.RemoveUserClientRoles(ctx, user.ID, targetUUID, roles)
				recordKeycloakAPI(opRemoveUserClientRoles, err)
				return err
			})
		changed = changed || clientChanged
		if err != nil {
			return changed, fmt.Errorf("converging the %q roles of Keycloak client %q's service account: %w", clientID, kclient.Spec.ClientID, err)
		}
	}
	return changed, nil
}

// realmDefaultRole returns the name of the realm's default role, fetching the
// realm once per instance and caching the name, which does not change.
func (r *ClientReconciler) realmDefaultRole(ctx context.Context, kc ClientClient, kclient *keycloakv1alpha1.Client) (string, error) {
	ref := kclient.Spec.InstanceRef
	namespace := ref.Namespace
	if namespace == "" {
		namespace = kclient.Namespace
	}
	key := namespace + "/" + ref.Name
	if name, ok := r.defaultRoles.Load(key); ok {
		return name.(string), nil
	}
	realm, err := kc.GetRealm(ctx)
	recordKeycloakAPI(opGetRealm, err)
	if err != nil {
		return "", fmt.Errorf("getting the realm's default role: %w", err)
	}
	name := ""
	if realm.DefaultRole != nil {
		name = realm.DefaultRole.Name
	}
	r.defaultRoles.Store(key, name)
	return name, nil
}

// convergeRoles makes held exactly the roles named in want. It resolves every
// missing role before changing anything, then removes the extras and adds the
// missing ones, and reports whether it changed anything.
func convergeRoles(want []string, held []keycloak.ClientRole, resolve func(string) (*keycloak.ClientRole, error), add, remove func([]keycloak.ClientRole) error) (bool, error) {
	missing, extra := planSet(want, held, func(role keycloak.ClientRole) string { return role.Name })
	var toAdd []keycloak.ClientRole
	for _, name := range missing {
		role, err := resolve(name)
		if err != nil {
			return false, err
		}
		toAdd = append(toAdd, *role)
	}
	changed := false
	if len(extra) > 0 {
		if err := remove(extra); err != nil {
			return false, err
		}
		changed = true
	}
	if len(toAdd) > 0 {
		if err := add(toAdd); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// planSet compares the items held with the names wanted. It returns the wanted
// names that are not held, sorted, and the held items that are not wanted.
func planSet[T any](want []string, held []T, name func(T) string) (missing []string, extra []T) {
	wanted := make(map[string]bool, len(want))
	for _, n := range want {
		wanted[n] = true
	}
	have := make(map[string]bool, len(held))
	for _, item := range held {
		have[name(item)] = true
		if !wanted[name(item)] {
			extra = append(extra, item)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(wanted)) {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	return missing, extra
}
