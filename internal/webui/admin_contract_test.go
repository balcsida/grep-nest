package webui

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestAdminDocumentContract(t *testing.T) {
	if len(adminDocument) >= 40<<10 {
		t.Fatalf("admin document bytes=%d", len(adminDocument))
	}
	for _, want := range []string{
		`data-grepnest-admin`, `id="admin-shell"`, `id="access-panel"`,
		`data-screen="overview"`, `data-screen="repositories"`, `data-screen="queue"`,
		`data-screen="scip"`, `data-screen="webhooks"`, `data-screen="github"`,
		`id="repo-filter"`, `id="repo-statuses"`, `id="reconcile"`, `id="reindex-selected"`,
		`id="scip-upload"`, `id="dependency-refresh"`, `id="admin-status"`,
		`id="inventory-notices"`, `id="load-older-jobs"`, `Load older jobs`,
		`jobsCursor:null`, `async function loadOlderJobs()`, `encodeURIComponent(state.jobsCursor)`,
		`href="/"`, `sessionStorage`, `prefers-reduced-motion: reduce`,
		`/v1/admin/overview`, `/v1/admin/repositories`, `/v1/admin/jobs`,
		`/v1/admin/scip/uploads`, `/v1/admin/scip/dependencies`,
		`/v1/admin/webhook-deliveries`, `/v1/admin/github`,
		`/v1/scip/uploads`, `/v1/scip/dependencies/github`, `/healthz`, `/readyz`,
		`button{min-width:44px}`, `.aside-foot a{min-height:44px;display:flex;align-items:center}`,
		`input[type=checkbox]{width:44px;min-width:44px}`,
		`.toolbar>:not(.sr){width:100%}`,
		`<th>GitHub ID</th><th>Repository</th><th>Branch</th><th>Status</th><th>Error code</th>`,
		`<th>Target ref</th><th>Target SHA</th><th>State</th><th>Attempts</th><th>Reason</th><th>Error code</th>`,
		`<th>Outcome</th><th>Received</th><th>Processed</th>`,
	} {
		if !bytes.Contains(adminDocument, []byte(want)) {
			t.Errorf("admin document missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"localStorage", "innerHTML", "outerHTML", "insertAdjacentHTML",
		"support.js", "fonts.googleapis.com", "private_key_path", "webhook_secret_path",
		"Search nodes", "search_nodes",
	} {
		if bytes.Contains(adminDocument, []byte(forbidden)) {
			t.Errorf("admin document contains forbidden %q", forbidden)
		}
	}
}

func TestAdminIdentityManagementContract(t *testing.T) {
	for _, want := range []string{
		`data-screen="users"`, `data-screen="groups"`, `Users`, `Groups`,
		`Effective access`, `Direct access`, `Suspend user`, `Revoke credentials`,
		`/v1/admin/users`, `/v1/admin/groups`, `/access`, `/suspend`, `/restore`, `/revoke-credentials`,
		`API tokens`, `Create API token`, `Revoke token`, `/v1/account/api-tokens`,
		`data-screen="audit"`, `Audit events`, `/v1/admin/audit-events`,
		`window.confirm`, `credentials:"same-origin"`,
	} {
		if !bytes.Contains(adminDocument, []byte(want)) {
			t.Errorf("admin identity management missing %q", want)
		}
	}
	for _, forbidden := range []string{`/scim/`, `SCIM profile`, `Manage membership`} {
		if bytes.Contains(adminDocument, []byte(forbidden)) {
			t.Errorf("admin identity management contains forbidden %q", forbidden)
		}
	}
}

func TestAdminDOMContract(t *testing.T) {
	command := exec.Command(requireNode(t), "admin_dom_test.mjs")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("admin DOM contract: %v\n%s", err, output)
	}
}

func TestAdminDocumentHidesContentUntilAuthorization(t *testing.T) {
	for _, want := range []string{
		`id="admin-shell" hidden`, `response.status===401`, `response.status===403`,
		`response.status===404`, `shell.hidden=false`, `textContent`,
		`window.confirm`, `setInterval`, `aria-live="polite"`,
		`[hidden]{display:none!important}`,
		`#admin-shell{grid-template-columns:minmax(0,1fr)}`,
	} {
		if !bytes.Contains(adminDocument, []byte(want)) {
			t.Errorf("admin lifecycle missing %q", want)
		}
	}
}

func TestAdminPrefersSameOriginOIDCSessionBeforeBearerFallback(t *testing.T) {
	for _, want := range []string{
		`/v1/auth/config`, `/v1/auth/session`, `Sign in with SSO`,
		`credentials:"same-origin"`, `/auth/logout`, `await logout()`, `enterBearer`,
	} {
		if !bytes.Contains(adminDocument, []byte(want)) {
			t.Errorf("admin document missing OIDC session behavior %q", want)
		}
	}
	for _, forbidden := range []string{`localStorage`, `sessionStorage.setItem("grepnest_session`} {
		if bytes.Contains(adminDocument, []byte(forbidden)) {
			t.Errorf("admin stores a session credential %q", forbidden)
		}
	}
}

func TestAdminRequiresSuccessfulLogoutBeforeBearerFallback(t *testing.T) {
	for _, want := range []string{`response.status!==204`, `await logout();mode="bearer"`, `showAccess("Unable to sign out.")`} {
		if !bytes.Contains(adminDocument, []byte(want)) {
			t.Errorf("admin does not gate bearer fallback on logout: %q", want)
		}
	}

}
