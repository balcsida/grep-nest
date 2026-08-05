package webui

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestConsoleProvidesBearerTokenSignInWithoutUnsupportedProviders(t *testing.T) {
	for _, forbidden := range []string{
		`Continue with GitHub`,
		`Continue with SSO (SAML)`,
		`id="provider-help"`,
		`button:disabled{cursor:not-allowed;opacity:.65}`,
	} {
		if bytes.Contains(document, []byte(forbidden)) {
			t.Fatalf("console still offers unsupported provider %q", forbidden)
		}
	}
	for _, want := range []string{
		`id="token-gate"`,
		`id="token-form"`,
		`<label for="token">Bearer token</label>`,
		`<button class="connect" type="submit">Connect</button>`,
		`#token-gate{display:grid;min-height:100vh;place-items:center`,
		`.connect{background:var(--accent);border-color:var(--accent)`,
	} {
		if !bytes.Contains(document, []byte(want)) {
			t.Fatalf("console is missing usable bearer-token gate %q", want)
		}
	}
}

func TestConsoleRendersTrustedProviderMetadataGenerically(t *testing.T) {
	script, err := elementBody(string(document), "script")
	if err != nil {
		t.Fatal(err)
	}
	render, err := functionBody(script, "providers")
	if err != nil {
		t.Fatal(err)
	}
	harness := `
const links=[],host={replaceChildren(){links.length=0},append(link){links.push(link)}},document={
  createDocumentFragment(){return {children:[],append(link){this.children.push(link)}}},
  createElement(){return {}},
},$=()=>host,location={origin:"https://grepnest.example"};
` + render + `
providers([
  {label:"Corporate identity",login_url:"/auth/oidc/login"},
  {label:"Code host",login_url:"/auth/oauth/github/login"},
  {label:"External",login_url:"https://evil.example/login"},
  {label:"Protocol relative",login_url:"//evil.example/login"},
  {label:"Backslash external",login_url:"/\\evil.example/login"},
  null,
  {label:"Missing URL"},
  {label:"Numeric URL",login_url:7},
]);
if(JSON.stringify(links.map(link=>[link.textContent,link.href]))!==JSON.stringify([
  ["Corporate identity","/auth/oidc/login"],["Code host","/auth/oauth/github/login"]
]))throw new Error("untrusted or reordered provider links: "+JSON.stringify(links));
`
	if output, err := exec.Command(requireNode(t), "-e", harness).CombinedOutput(); err != nil {
		t.Fatalf("provider metadata contract failed: %v\n%s", err, output)
	}
}

func TestConsolePrefersSameOriginBrowserSessionBeforeBearerFallback(t *testing.T) {
	for _, want := range []string{
		`/v1/auth/config`, `/v1/auth/session`, `Sign in with SSO`,
		`credentials:"same-origin"`, `/auth/logout`, `await logout()`, `enterBearer`,
	} {
		if !bytes.Contains(document, []byte(want)) {
			t.Errorf("console is missing OIDC session behavior %q", want)
		}
	}
	for _, forbidden := range []string{`localStorage`, `sessionStorage.setItem("grepnest_session`} {
		if bytes.Contains(document, []byte(forbidden)) {
			t.Errorf("console stores a session credential %q", forbidden)
		}
	}
}

func TestConsoleReadsStaticFileCapabilityFromAuthConfig(t *testing.T) {
	script, err := elementBody(string(document), "script")
	if err != nil {
		t.Fatal(err)
	}
	start, err := functionBody(script, "start")
	if err != nil {
		t.Fatal(err)
	}
	harness := `
const elements={"token-form":{hidden:false}},$=id=>elements[id],state={fileReads:false};
const providers=()=>{},session=()=>{},auth=()=>{};
let calls,payload;
const api=async()=>++calls===1?{ok:true,json:async()=>({providers:[],token_login:true,file_reads:payload})}:{ok:false};
async ` + start + `
for(const [value,want] of [[false,false],[true,true],["yes",false]]){
  payload=value;calls=0;await start();
  if(state.fileReads!==want)throw new Error(typeof value+" auth config mapped to "+state.fileReads);
}
`
	if output, err := exec.Command(requireNode(t), "--input-type=module", "-e", harness).CombinedOutput(); err != nil {
		t.Fatalf("auth file-read capability failed: %v\n%s", err, output)
	}
}

func TestConsoleRequiresSuccessfulLogoutBeforeBearerFallback(t *testing.T) {
	for _, want := range []string{`status!==204`, `await logout();enterBearer(t)`, `reportValidity()`} {
		if !bytes.Contains(document, []byte(want)) {
			t.Errorf("console does not gate bearer fallback on logout: %q", want)
		}
	}
}

func TestConsoleProvidesFunctionalSearchFiltersAndExamples(t *testing.T) {
	for _, want := range []string{
		`id="language-filter"`,
		`<option value="">All languages</option>`,
		`function queryWithLanguage(query)`,
		`query:queryWithLanguage($("query").value)`,
		`data-query="lang:go -test NewService"`,
		`data-query="case:yes repo:payments Token"`,
		`function useExample(button)`,
	} {
		if !bytes.Contains(document, []byte(want)) {
			t.Fatalf("console is missing functional search aid %q", want)
		}
	}
}

func TestConsolePluralizesResultCounts(t *testing.T) {
	script, err := elementBody(string(document), "script")
	if err != nil {
		t.Fatal(err)
	}
	countLabel, err := functionBody(script, "countLabel")
	if err != nil {
		t.Fatal(err)
	}
	harness := countLabel + `
if(countLabel(1,"match")!=="1 match")throw new Error("singular match");
if(countLabel(2,"match")!=="2 matches")throw new Error("plural matches");
if(countLabel(2,"repository")!=="2 repositories")throw new Error("plural repositories");
`
	if output, err := exec.Command(requireNode(t), "-e", harness).CombinedOutput(); err != nil {
		t.Fatalf("count grammar failed: %v\n%s", err, output)
	}
}

func TestConsoleProvidesAccessibleQuerySyntaxDrawer(t *testing.T) {
	for _, want := range []string{
		`id="syntax-toggle"`,
		`id="syntax-drawer"`,
		`aria-labelledby="syntax-title"`,
		`file:\.go$`,
		`repo:payments`,
		`"exact phrase"`,
		`function setSyntaxOpen(open,trigger)`,
		`setSyntaxOpen(true,$("syntax-rail"))`,
		`event.key==="Escape"`,
	} {
		if !bytes.Contains(document, []byte(want)) {
			t.Fatalf("console is missing query syntax behavior %q", want)
		}
	}
}

func TestConsoleExplainsZoektQueryComposition(t *testing.T) {
	for _, want := range []string{
		`Queries use Zoekt syntax.`,
		`Regular expressions are enabled by default.`,
		`Combine filters with spaces.`,
		`Prefix a term with - to negate it.`,
	} {
		if !bytes.Contains(document, []byte(want)) {
			t.Fatalf("console is missing query guidance %q", want)
		}
	}
}

func TestSyntaxDrawerRestoresItsConnectedOpenerOrQuery(t *testing.T) {
	script, err := elementBody(string(document), "script")
	if err != nil {
		t.Fatal(err)
	}
	setSyntaxOpen, err := functionBody(script, "setSyntaxOpen")
	if err != nil {
		t.Fatal(err)
	}
	harness := `
const focused=[];
const elements={
  "syntax-drawer":{hidden:true},
  "syntax-toggle":{setAttribute(){}},
  "syntax-close":{focus(){focused.push("close")}},
  query:{isConnected:true,focus(){focused.push("query")}}
};
const $=id=>elements[id],state={syntaxTrigger:null};
const document={activeElement:null};
` + setSyntaxOpen + `
const opener={isConnected:true,focus(){focused.push("opener")}};
document.activeElement=opener;setSyntaxOpen(true);
document.activeElement={isConnected:true};setSyntaxOpen(false);
if(focused.at(-1)!=="opener")throw new Error("connected opener was not restored");
document.activeElement=opener;setSyntaxOpen(true);opener.isConnected=false;
document.activeElement={isConnected:true};setSyntaxOpen(false);
if(focused.at(-1)!=="query")throw new Error("query fallback was not restored");
`
	if output, err := exec.Command(requireNode(t), "-e", harness).CombinedOutput(); err != nil {
		t.Fatalf("drawer behavior failed: %v\n%s", err, output)
	}
}

func TestConsoleGuidesRepositoryLoadingErrorAndEmptyStates(t *testing.T) {
	for _, want := range []string{
		`$("repository-status").textContent="Loading authorized repositories…";`,
		`"Repository list is unavailable. Search still covers every authorized repository."`,
		`"No authorized repositories are available for this token."`,
		`state.repositories.length===0`,
	} {
		if !bytes.Contains(document, []byte(want)) {
			t.Fatalf("console is missing repository state %q", want)
		}
	}
}
