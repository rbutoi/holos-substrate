package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClientType is the OIDC client type: a public client (SPA/CLI, no
// secret, PKCE) or a confidential client (authenticated by a delivered secret).
// It mirrors the public (argocd/kargo) vs confidential (quay) distinction in
// the platform realm (keycloak-clients.md).
//
// +kubebuilder:validation:Enum=public;confidential
type ClientType string

const (
	// ClientTypePublic is a public OIDC client (no client secret, PKCE).
	ClientTypePublic ClientType = "public"
	// ClientTypeConfidential is a confidential OIDC client authenticated
	// by a delivered client secret.
	ClientTypeConfidential ClientType = "confidential"
)

// PKCEMethod is the PKCE code-challenge method a client requires on the
// authorization code flow.
//
// +kubebuilder:validation:Enum=S256;None
type PKCEMethod string

const (
	// PKCEMethodS256 requires PKCE with the SHA-256 code-challenge method.
	PKCEMethodS256 PKCEMethod = "S256"
	// PKCEMethodNone does not require PKCE.
	PKCEMethodNone PKCEMethod = "None"
)

// ClientServiceAccount is a client's service account, which lets the client
// authenticate as itself with the client credentials grant, and the roles it
// holds. Both role lists are complete: a role the service account holds but the
// lists do not name is removed, except the realm's default role, which Keycloak
// grants every user.
type ClientServiceAccount struct {
	// RealmRoles are the realm roles granted to the service account.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=255
	RealmRoles []string `json:"realmRoles,omitempty"`

	// ClientRoles are the client roles granted to the service account, each
	// named by the clientId of the client that defines it.
	//
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	ClientRoles []ServiceAccountClientRole `json:"clientRoles,omitempty"`
}

// ServiceAccountClientRole names one client role to grant a service account.
type ServiceAccountClientRole struct {
	// ClientID is the Keycloak clientId of the client that defines the role,
	// for example realm-management.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	ClientID string `json:"clientId"`

	// Role is the name of the client role.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Role string `json:"role"`
}

// ClientSecretReference names where a confidential client's generated client
// secret is delivered. The reconciler writes a generate-once, create-if-absent
// Secret in the resource's own namespace per the secret-handling guardrail — it
// is never committed, mirroring the platform's quay-oidc bootstrap. It is
// distinct from the spec-level credentialsSecretRef (the admin credential): this
// points at the per-client delivered secret.
type ClientSecretReference struct {
	// Name of the Secret in the resource's namespace to deliver the client secret
	// into.
	//
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key within the Secret to write the client secret under.
	//
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// ClientFlows selects which OAuth 2.0 flows a client may use. A flow that is
// omitted is left as it is in Keycloak; true allows it and false disallows it.
type ClientFlows struct {
	// StandardFlow allows the authorization code flow, the browser sign-in most
	// clients use.
	//
	// +optional
	StandardFlow *bool `json:"standardFlow,omitempty"`

	// DirectAccessGrants allows the resource owner password credentials grant,
	// in which the client itself collects and sends a user's username and
	// password.
	//
	// +optional
	DirectAccessGrants *bool `json:"directAccessGrants,omitempty"`

	// Implicit allows the implicit flow, which returns tokens directly from the
	// authorization endpoint.
	//
	// +optional
	Implicit *bool `json:"implicit,omitempty"`
}

// ClientSpec defines the desired state of a Client: one project
// OIDC client named by its URL, its redirect/web-origin configuration, the
// client roles it defines, the group→groups-claim mapping (via client roles),
// and — for a confidential client — where to deliver the generated secret
// (ADR-20).
//
// The group→groups-claim mechanism (ADR-20): because Keycloak's Group
// Membership mapper cannot synthesize an arbitrary claim value from a path, a
// role group carries a client-role assignment (see ClientRoles) and the existing
// oidc-usermodel-client-role-mapper emits the role name into the shared groups
// claim (repo precedent in holos/components/keycloak/realm-config/buildplan.cue).
//
// +kubebuilder:validation:XValidation:rule="self.type == 'confidential' ? has(self.secretRef) : !has(self.secretRef)",message="secretRef is required for a confidential client and forbidden for a public client"
// +kubebuilder:validation:XValidation:rule="!(self.type == 'public' && has(self.pkceMethod) && self.pkceMethod == 'None')",message="a public client must require PKCE; pkceMethod None is only allowed for a confidential client"
// +kubebuilder:validation:XValidation:rule="!has(self.serviceAccount) || self.type == 'confidential'",message="serviceAccount is only allowed for a confidential client"
// +kubebuilder:validation:XValidation:rule="!has(self.defaultClientScopes) || !has(self.optionalClientScopes) || self.defaultClientScopes.all(s, !(s in self.optionalClientScopes))",message="a client scope cannot be both a default and an optional scope"
type ClientSpec struct {
	// ClientID is the Keycloak client ID, named by its URL (e.g.
	// https://quay.holos.internal). It is immutable: it is the client's durable
	// identity in the realm's global client namespace, so the ownership claim and
	// the finalizer always target exactly the client this CR provisioned.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="clientId is immutable"
	ClientID string `json:"clientId"`

	// Type is the OIDC client type, public or confidential. It is immutable: a
	// public<->confidential transition would strand the per-client artifacts keyed
	// to the prior type (a confidential->public edit would orphan the delivered
	// client-secret Secret; a public->confidential edit would need a freshly
	// generated secret and a redirect/PKCE re-evaluation), so the type is fixed for
	// the client's life — recreate the resource to change it.
	//
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"
	Type ClientType `json:"type"`

	// InstanceRef references the Instance this client is provisioned in. A
	// cross-namespace reference (Namespace set to a different namespace) is gated
	// by a security.holos.run ReferenceGrant in the instance's namespace. It is
	// immutable: retargeting a provisioned client to another instance would create
	// a second OIDC client in the new realm and orphan the original (the finalizer
	// can no longer reach it), so the target realm is fixed for the client's life.
	//
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="instanceRef is immutable"
	InstanceRef InstanceReference `json:"instanceRef"`

	// RedirectURIs are the allowed OAuth2 redirect URIs for the client.
	//
	// +optional
	// +listType=set
	RedirectURIs []string `json:"redirectUris,omitempty"`

	// WebOrigins are the allowed CORS web origins for the client.
	//
	// +optional
	// +listType=set
	WebOrigins []string `json:"webOrigins,omitempty"`

	// PostLogoutRedirectURIs are the URIs Keycloak may send a user back to after
	// they sign out, when the client names one in its logout request. When
	// omitted, the client's post-logout redirect URIs are left as they are in
	// Keycloak.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=2048
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris,omitempty"`

	// Description is free text propagated to the Keycloak client's native
	// Description attribute. When omitted the client's description converges to
	// empty (the reconciler sends the spec value unconditionally on update, so a
	// console-set description is corrected back to the spec on every reconcile).
	//
	// +optional
	Description string `json:"description,omitempty"`

	// DisplayName is the client's name as shown in the Keycloak admin console and
	// on the login and consent screens. When omitted, a client this resource
	// creates is named after its metadata.name, and the name is not managed
	// afterwards, so a name set in the console is left alone.
	//
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	DisplayName *string `json:"displayName,omitempty"`

	// RootURL is the client's root URL, which Keycloak prepends to relative
	// redirect URIs and to the base URL. When omitted, the client's root URL is
	// left as it is in Keycloak.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	RootURL *string `json:"rootUrl,omitempty"`

	// BaseURL is the URL Keycloak links to when it sends a user back to the
	// client, for example from the account console. When omitted, the client's
	// base URL is left as it is in Keycloak.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	BaseURL *string `json:"baseUrl,omitempty"`

	// Flows selects which OAuth 2.0 flows the client may use. When omitted, or
	// for any flow it does not name, the client's setting is left as it is in
	// Keycloak.
	//
	// +optional
	Flows *ClientFlows `json:"flows,omitempty"`

	// PKCEMethod is the PKCE code-challenge method the client requires on the
	// authorization code flow: S256 requires PKCE, and None does not. When
	// omitted, a public client requires S256 and a confidential client does not
	// require PKCE. A public client cannot be set to None, because without a
	// client secret PKCE is what protects its authorization codes.
	//
	// +optional
	PKCEMethod PKCEMethod `json:"pkceMethod,omitempty"`

	// ServiceAccount, when set, enables the client's service account and grants
	// it exactly the listed roles. Only a confidential client can have one. When
	// omitted, the client's service account and its roles are left as they are in
	// Keycloak.
	//
	// +optional
	ServiceAccount *ClientServiceAccount `json:"serviceAccount,omitempty"`

	// DefaultClientScopes are the client scopes added to every token the client
	// requests, by name. The list is complete: a default scope the client has but
	// the list does not name is removed. When omitted, the client's default
	// scopes are left as they are in Keycloak.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=255
	DefaultClientScopes []string `json:"defaultClientScopes,omitempty"`

	// OptionalClientScopes are the client scopes added to a token only when the
	// client requests them, by name. The list is complete: an optional scope the
	// client has but the list does not name is removed. When omitted, the
	// client's optional scopes are left as they are in Keycloak. A scope cannot
	// be both default and optional.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=255
	OptionalClientScopes []string `json:"optionalClientScopes,omitempty"`

	// ClientRoles optionally lists the client roles defined on this client — the
	// primitive owner/editor/viewer triad scoped to this one client. A role group
	// (Group) assigns one of these, and the per-client
	// oidc-usermodel-client-role-mapper emits the role name into the shared groups
	// claim (the group→claim mechanism, ADR-20). Each entry's ClientRef is this
	// Client's own metadata.name (the object name, not the URL-shaped
	// clientId — see ClientRoleReference). The role is always defined on THIS
	// client, so an entry's clientId — meaningful only for Group, where it
	// names a foreign target client — is forbidden here: the CEL rule rejects it so
	// an accepted spec never carries a silently-ignored target field.
	//
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(r, !has(r.clientId))",message="clientRoles on a Client may not set clientId; a client defines roles on itself (use clientRef naming this client)"
	ClientRoles []ClientRoleReference `json:"clientRoles,omitempty"`

	// SecretRef names where a confidential client's generated secret is delivered
	// (a generate-once Secret in this resource's namespace). It is required for a
	// confidential client and forbidden for a public client (a public client
	// carries no secret) — enforced by a CEL validation on this spec, so the
	// type/secretRef pair is always consistent at admission.
	//
	// +optional
	SecretRef *ClientSecretReference `json:"secretRef,omitempty"`

	// CABundle carries PEM-encoded x509 CA certificates the controller trusts in
	// addition to its system store when reaching the Keycloak admin API for this
	// client. Its semantics and serialization are the shared "CABundle convention"
	// documented once in common_types.go: an empty value uses the controller pod's
	// system trust store unchanged. It is the trust anchor for an in-cluster
	// Keycloak signed by the platform's local CA.
	//
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`

	// Adopt opts in to taking ownership of a pre-existing Keycloak client of the
	// same clientId (the claim model, mirroring ADR-19's Organization). Default
	// false: because a Keycloak client lives in the realm's single global client
	// namespace while this CR is Kubernetes-namespaced, a client this CR did not
	// create and does not already own is a Conflict (Ready=False, reason Conflict)
	// and is never silently seized or reconfigured. Set adopt: true to deliberately
	// claim and converge such a client. When this resource is deleted, an adopted
	// client is released unless deletionPolicy is Delete.
	//
	// +optional
	Adopt bool `json:"adopt,omitempty"`

	// DeletionPolicy controls how the controller handles the Keycloak client when
	// this resource is deleted. Delete removes the client after verifying the live
	// client still has the UUID recorded in status. Orphan leaves the client
	// untouched. When omitted, a client this resource created is deleted, while an
	// adopted client is released without deleting it.
	//
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// ClientStatus defines the observed state of a Client, following
// the Gateway-API status convention.
type ClientStatus struct {
	// Conditions represent the latest available observations of the client's
	// state.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// ObservedGeneration is the most recent generation observed for this
	// Client by the controller.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Created records whether this CR created the Keycloak client (true) versus
	// adopted a pre-existing client of the same clientId (false). The finalizer
	// deletes the Keycloak client only when Created is true; an adopted client is
	// released, never deleted.
	//
	// +optional
	Created bool `json:"created,omitempty"`

	// Adopted records whether this CR adopted a pre-existing Keycloak client of
	// the same clientId rather than creating it. An adopted client is released,
	// never deleted, on CR removal.
	//
	// +optional
	Adopted bool `json:"adopted,omitempty"`

	// ClientUUID is the Keycloak UUID of the client this CR owns or adopted. It is
	// the immutable handle the reconciler converges roles/mapper/secret against and
	// the finalizer verifies before deleting — recorded so a re-run targets exactly
	// the client this CR provisioned, and a UUID mismatch (the client was replaced
	// out of band at the same clientId) is a Conflict rather than a silent seizure.
	//
	// +optional
	ClientUUID string `json:"clientUUID,omitempty"`

	// LastValidatedTime is the last time the controller successfully read
	// Keycloak and confirmed or restored the declared client state. It is not
	// advanced on failed remote reads or failed verification, so stale values
	// remain visible.
	//
	// +optional
	LastValidatedTime *metav1.Time `json:"lastValidatedTime,omitempty"`

	// LastMutatedTime is the last time the controller actually changed Keycloak
	// for this client, such as creating/updating the client or programming its
	// roles and mapper.
	//
	// +optional
	LastMutatedTime *metav1.Time `json:"lastMutatedTime,omitempty"`

	// LastMutationReason classifies the cause of the last remote mutation. It is
	// written together with lastMutatedTime.
	//
	// +optional
	// +kubebuilder:validation:Enum=SpecChange;DriftRemediation
	LastMutationReason MutationReason `json:"lastMutationReason,omitempty"`

	// LastDriftTime is the last time the controller remediated out-of-band drift.
	// It is set with LastMutationReason=DriftRemediation and preserved across
	// later spec-driven mutations.
	//
	// +optional
	LastDriftTime *metav1.Time `json:"lastDriftTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={holos,keycloak}
// +kubebuilder:printcolumn:name="ClientID",type=string,JSONPath=`.spec.clientId`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Validated",type=date,priority=1,JSONPath=`.status.lastValidatedTime`

// Client is the Schema for the clients API. It manages one
// project OIDC client named by its URL and the group→groups-claim mapping via
// client roles (ADR-20).
type Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClientSpec   `json:"spec,omitempty"`
	Status ClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClientList contains a list of Client.
type ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Client `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Client{}, &ClientList{})
}
