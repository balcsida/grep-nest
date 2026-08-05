#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
chart=$(CDPATH= cd -- "$script_dir/.." && pwd)
minimal=$chart/ci/minimal-values.yaml
optional=$chart/ci/optional-values.yaml
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 HUP INT TERM

require() {
  [ -f "$2" ] && [ -r "$2" ] || {
    echo "not a readable regular file: $2" >&2
    return 2
  }
  if grep -E -q -e "$1" "$2"; then
    return 0
  else
    status=$?
  fi
  [ "$status" -eq 1 ] || {
    echo "grep failed with status $status for $2" >&2
    return "$status"
  }
  echo "missing $1 in $2" >&2
  return 1
}

reject() {
  [ -f "$2" ] && [ -r "$2" ] || {
    echo "not a readable regular file: $2" >&2
    return 2
  }
  if grep -E -n -e "$1" "$2"; then
    echo "forbidden $1 in $2" >&2
    return 1
  else
    status=$?
  fi
  [ "$status" -eq 1 ] || {
    echo "grep failed with status $status for $2" >&2
    return "$status"
  }
}

expect_failure() {
  output=$1
  shift
  if "$@" >/dev/null 2>"$output"; then
    echo "expected failure passed: $*" >&2
    return 1
  else
    status=$?
  fi
  [ "$status" -gt 0 ] && [ -s "$output" ] || {
    echo "expected nonzero failure with diagnostics: $*" >&2
    return 1
  }
}

expect_failure "$tmp/require-missing.err" require anything "$tmp/missing"
expect_failure "$tmp/reject-missing.err" reject anything "$tmp/missing"
require 'not a readable regular file:' "$tmp/require-missing.err"
require 'not a readable regular file:' "$tmp/reject-missing.err"
: >"$tmp/probe"
expect_failure "$tmp/require-grep.err" require '[' "$tmp/probe"
expect_failure "$tmp/reject-grep.err" reject '[' "$tmp/probe"
require 'grep failed with status 2' "$tmp/require-grep.err"
require 'grep failed with status 2' "$tmp/reject-grep.err"

helm lint "$chart" -f "$minimal"
helm template pilot "$chart" -n grepnest -f "$minimal" >"$tmp/minimal.yaml"
helm template pilot "$chart" -n grepnest -f "$minimal" -f "$optional" \
  --api-versions monitoring.coreos.com/v1/ServiceMonitor >"$tmp/optional.yaml"
helm template pilot "$chart" -n grepnest -f "$minimal" \
  --set=graph.mode=embedded >"$tmp/graph-embedded.yaml"
helm template uid-embedded "$chart" -n grepnest -f "$minimal" \
  --set=graph.mode=embedded \
  --set=server.podSecurityContext.runAsUser=1001230000 \
  --set=node.podSecurityContext.runAsUser=1001230001 >"$tmp/uid-embedded.yaml"
helm template pilot "$chart" -n grepnest -f "$minimal" -f "$optional" \
  --set=graph.mode=separate \
  --api-versions monitoring.coreos.com/v1/ServiceMonitor >"$tmp/graph-separate.yaml"
helm template uid-separate "$chart" -n grepnest -f "$minimal" \
  --set=graph.mode=separate \
  --set=server.podSecurityContext.runAsUser=1001230002 \
  --set=graph.podSecurityContext.runAsUser=1001230003 >"$tmp/uid-separate.yaml"
expect_failure "$tmp/graph-mode.err" helm template bad "$chart" -f "$minimal" \
  --set=graph.mode=invalid
require "/graph/mode.*embedded.*separate" "$tmp/graph-mode.err"
helm template scanner-off "$chart" -n grepnest -f "$minimal" \
  --set=scanner.enabled=false \
  --set-string=images.scanner.repository= \
  --set-string=images.scanner.digest= >"$tmp/scanner-off.yaml"
expect_failure "$tmp/scanner-image.err" helm template bad "$chart" -f "$minimal" \
  --set=scanner.enabled=true \
  --set-string=images.scanner.repository= \
  --set-string=images.scanner.digest=
require "/images/scanner/(repository|digest)" "$tmp/scanner-image.err"
helm template scim "$chart" -n grepnest -f "$minimal" \
  --set=server.scim.enabled=true \
  --set-string=server.sso.publicURL=https://grepnest.example.invalid \
  --set-string=secrets.scim.name=grepnest-scim >"$tmp/scim.yaml"
helm template break-glass "$chart" -n grepnest -f "$minimal" \
  -f "$optional" --set=breakGlass.enabled=true \
  --api-versions monitoring.coreos.com/v1/ServiceMonitor >"$tmp/break-glass.yaml"
helm template github-oauth "$chart" -n grepnest -f "$minimal" \
  --set=server.sso.githubOAuth.enabled=true \
  --set-string=server.sso.githubOAuth.clientID=grepnest-github \
  --set-string=server.sso.publicURL=https://grepnest.example.invalid \
  --set-string=secrets.githubOAuth.name=grepnest-github-oauth >"$tmp/github-oauth.yaml"
helm template github-break-glass "$chart" -n grepnest -f "$minimal" \
  --set=breakGlass.enabled=true \
  --set=server.sso.githubOAuth.enabled=true \
  --set-string=server.sso.githubOAuth.clientID=grepnest-github \
  --set-string=server.sso.publicURL=https://grepnest.example.invalid \
  --set-string=secrets.githubOAuth.name=grepnest-github-oauth >"$tmp/github-break-glass.yaml"
long_release=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzx
helm template "$long_release" "$chart" -n grepnest -f "$minimal" >"$tmp/long-release.yaml"

awk '
  /^[[:space:]]*(name|serviceName|serviceAccountName): [^{}]/ {
    value = $2
    gsub(/^"|"$/, "", value)
    if (length(value) > 63) {
      print "name exceeds 63 characters: " value > "/dev/stderr"
      failed = 1
    }
  }
  END { exit failed }
' "$tmp/long-release.yaml"
for suffix in server node zoekt indexer migrate deny-ingress allow-server-ingress \
  allow-zoekt-ingress allow-indexer-metrics-ingress graph allow-graph-ingress; do
  [ "$(grep -E -c -e "^  name: .*$suffix\$" "$tmp/long-release.yaml")" -ge 1 ] || exit 1
done
[ "$(sed -n 's/^  name: //p' "$tmp/long-release.yaml" | sort -u | \
  grep -E -c -e '-(server|node|zoekt|indexer|migrate|deny-ingress|allow-server-ingress|allow-zoekt-ingress|allow-indexer-metrics-ingress|graph|allow-graph-ingress)$')" \
  -eq 11 ] || exit 1

helm template paths "$chart" -n grepnest -f "$minimal" \
  --set-string=node.paths.data=/srv/grepnest-data \
  --set-string=node.paths.indexes=/srv/grepnest-data/zoekt/index \
  --set-string=graph.dataPath=/srv/grepnest-data/graph \
  --set=node.zoekt.port=16070 --set=node.service.port=16071 \
  --set=node.indexer.metricsPort=19090 >"$tmp/node-contract.yaml"
for pattern in \
  'GREPNEST_DATA_DIR: "/srv/grepnest-data"' \
  'GREPNEST_INDEX_DIR: "/srv/grepnest-data/zoekt/index"' \
  'GREPNEST_MIN_FREE_BYTES: "10737418240"' \
  'GREPNEST_MAX_REPOSITORY_BYTES: "5368709120"' \
	'GREPNEST_SCIP_MAX_UPLOAD_BYTES: "67108864"' \
  'containerPort: 16070' 'port: 16071, targetPort: zoekt' \
  'GREPNEST_METRICS_LISTEN_ADDRESS: ":19090"' \
  'name: metrics, containerPort: 19090' \
  'name: metrics, port: 19090, targetPort: metrics' \
  'mountPath: "/srv/grepnest-data/zoekt/index", subPath: "zoekt/index", readOnly: true' \
  'mountPath: "/srv/grepnest-data"}'; do
  require "$pattern" "$tmp/node-contract.yaml"
done
sed -n '/name: zoekt-webserver$/,/name: grepnest-indexer$/p' \
  "$tmp/node-contract.yaml" >"$tmp/node-contract-zoekt.yaml"
require '^- -index$|^            - -index$' "$tmp/node-contract-zoekt.yaml"
require '^            - "/srv/grepnest-data/zoekt/index"$' \
  "$tmp/node-contract-zoekt.yaml"
require '^- -listen$|^            - -listen$' "$tmp/node-contract-zoekt.yaml"
require '^            - ":16070"$' "$tmp/node-contract-zoekt.yaml"
[ "$(grep -E -c -e 'tcpSocket: \{port: zoekt\}' "$tmp/node-contract-zoekt.yaml")" -eq 2 ] || exit 1

expect_failure "$tmp/disconnected-indexes.err" helm template bad "$chart" -f "$minimal" \
  --set-string=node.paths.data=/srv/grepnest-data \
  --set-string=graph.dataPath=/srv/grepnest-data/graph \
  --set-string=node.paths.indexes=/srv/other/index
require 'node.paths.indexes must be a child of node.paths.data' "$tmp/disconnected-indexes.err"

helm template refs "$chart" -n grepnest -f "$minimal" \
  --set-string=secrets.runtime.name=runtime.team.example \
  --set-string=secrets.runtime.databaseURLKey=DB_URL.v1-key \
  --set-string=images.pullSecrets[0]=registry.team.example \
  --set-string=node.storage.storageClassName=ssd.storage.example >"$tmp/references.yaml"
for pattern in 'name: runtime.team.example' 'key: DB_URL.v1-key' \
  'name: registry.team.example' 'storageClassName: "ssd.storage.example"'; do
  require "$pattern" "$tmp/references.yaml"
done

helm template security "$chart" -n grepnest -f "$minimal" \
  --set=server.podSecurityContext.runAsNonRoot=false \
  --set=server.podSecurityContext.seccompProfile.type=Unconfined \
  --set=server.podSecurityContext.fsGroup=1234 \
  --set=node.podSecurityContext.runAsNonRoot=false \
  --set=node.podSecurityContext.seccompProfile.type=Unconfined \
  --set=node.podSecurityContext.fsGroup=2345 >"$tmp/pod-security.yaml"
sed -n '/^kind: Deployment$/,/^      containers:$/p' "$tmp/pod-security.yaml" \
  | sed -n '/^      securityContext:$/,$p' >"$tmp/server-pod-security.yaml"
sed -n '/^kind: StatefulSet$/,/^      containers:$/p' "$tmp/pod-security.yaml" \
  | sed -n '/^      securityContext:$/,$p' >"$tmp/node-pod-security.yaml"
for workload in server node; do
  security=$tmp/$workload-pod-security.yaml
  [ "$(awk '/^        runAsNonRoot: true$/ {count++} END {print count + 0}' "$security")" -eq 1 ] || exit 1
  [ "$(awk '/^        seccompProfile:/ {count++} END {print count + 0}' "$security")" -eq 1 ] || exit 1
  require 'type: RuntimeDefault' "$security"
  reject 'runAsNonRoot: false|type: Unconfined' "$security"
done
require '^        fsGroup: 1234$' "$tmp/server-pod-security.yaml"
require '^        fsGroup: 2345$' "$tmp/node-pod-security.yaml"

for manifest in "$tmp/minimal.yaml" "$tmp/optional.yaml"; do
  for pattern in \
    '^kind: Deployment$' '^kind: StatefulSet$' '^kind: Job$' \
    '^kind: ConfigMap$' '^kind: ServiceAccount$' '^kind: Service$' \
    '^kind: PodDisruptionBudget$' '^kind: NetworkPolicy$' \
    'type: ClusterIP' 'helm.sh/hook: pre-install,pre-upgrade' \
    'replicas: 1' 'ReadWriteOnce' 'storage: 250Gi' \
    'httpGet:' 'tcpSocket:' 'automountServiceAccountToken: false' \
    'allowPrivilegeEscalation: false' 'capabilities: \{drop: \[ALL\]\}' \
    'readOnlyRootFilesystem: true' 'runAsNonRoot: true' \
    'seccompProfile: \{type: RuntimeDefault\}' \
    'mountPath: /tmp' 'mountPath: /var/run/grepnest' \
    'requests:' 'limits:'; do
    require "$pattern" "$manifest"
  done
  reject '^kind: Secret$|apiVersion: .*openshift\.io|^kind: (Route|BuildConfig|ImageStream|Template|SecurityContextConstraints)$|:latest([[:space:]]|$)|hostPath:|privileged: true|allowPrivilegeEscalation: true|runAsUser: 0|type: (NodePort|LoadBalancer)' "$manifest"
  reject 'runAsNonRoot: false' "$manifest"

  images_file=$tmp/$(basename "$manifest").images
  if grep -E -e '^ *image:' "$manifest" >"$images_file"; then
    :
  else
    status=$?
    echo "image extraction failed with status $status for $manifest" >&2
    exit "$status"
  fi
  invalid_images=$tmp/$(basename "$manifest").invalid-images
  if grep -E -v -e '@sha256:[a-f0-9]{64}"?$' "$images_file" >"$invalid_images"; then
    echo "non-digest image in $manifest" >&2
    exit 1
  else
    status=$?
  fi
  [ "$status" -eq 1 ] || exit "$status"

  images=$(grep -E -c -e '^ *image:' "$images_file")
  for pattern in 'allowPrivilegeEscalation: false' 'capabilities: \{drop: \[ALL\]\}' \
    'readOnlyRootFilesystem: true'; do
    [ "$(grep -E -c -e "$pattern" "$manifest")" -eq "$images" ] || exit 1
  done
  workloads=$(grep -E -c -e '^kind: (Deployment|StatefulSet)$' "$manifest")
  [ "$(grep -E -c -e 'runAsNonRoot: true' "$manifest")" -eq "$((images + workloads))" ] || exit 1
  [ "$(grep -E -c -e 'seccompProfile: \{type: RuntimeDefault\}' "$manifest")" -ge "$images" ] || exit 1
  [ "$(grep -E -c -e '^kind: StatefulSet$' "$manifest")" -eq 1 ] || exit 1
  [ "$(grep -E -c -e '^  replicas: 1$' "$manifest")" -eq 1 ] || exit 1
  [ "$(grep -E -c -e '^        - name: (zoekt-webserver|grepnest-indexer)$' "$manifest")" -eq 2 ] || exit 1
done

for pattern in '^kind: Ingress$' '^kind: ServiceMonitor$' \
  'name: custom-ca' 'secretName: grepnest-existing-ca' \
  'grepnest.example.invalid/pool: server' \
  'grepnest.example.invalid/pool: node' \
  'grepnest.example.invalid/pool: migration' \
  'nodeSelector:' 'affinity:' 'tolerations:' \
  'grepnest.example.invalid/tier' \
  'grepnest.example.invalid/dedicated' \
  '- frontend$' '- storage$' '- batch$' \
  'value: server' 'value: node' 'value: migration' \
  'topologySpreadConstraints:' \
  'cpu: 250m' 'memory: 256Mi' 'cpu: "8"' 'memory: 24Gi'; do
  require "$pattern" "$tmp/optional.yaml"
done
[ "$(grep -E -c -e '^kind: ServiceMonitor$' "$tmp/optional.yaml")" -eq 4 ] || exit 1
require 'app.kubernetes.io/component: indexer' "$tmp/optional.yaml"
require 'app.kubernetes.io/component: graph-service' "$tmp/optional.yaml"
require 'app.kubernetes.io/component: scanner' "$tmp/optional.yaml"
require 'port: metrics' "$tmp/optional.yaml"

sed -n '/^kind: StatefulSet$/,/^# Source: grepnest\/templates\/migration-job.yaml$/p' \
  "$tmp/minimal.yaml" >"$tmp/node.yaml"
require '^kind: StatefulSet$' "$tmp/node.yaml"
[ "$(grep -E -c -e '^  volumeClaimTemplates:$' "$tmp/node.yaml")" -eq 1 ] || exit 1
sed -n '/^      containers:$/,/^      volumes:$/p' "$tmp/node.yaml" >"$tmp/node-containers.yaml"
require '^      containers:$' "$tmp/node-containers.yaml"
[ "$(grep -E -c -e '^        - name:' "$tmp/node-containers.yaml")" -eq 2 ] || exit 1
sed -n '/^        - name: zoekt-webserver$/,/^        - name: grepnest-indexer$/p' \
  "$tmp/node.yaml" >"$tmp/zoekt.yaml"
require '^        - name: zoekt-webserver$' "$tmp/zoekt.yaml"
sed -n '/^        - name: grepnest-indexer$/,/^      volumes:$/p' \
  "$tmp/node.yaml" >"$tmp/indexer.yaml"
require '^        - name: grepnest-indexer$' "$tmp/indexer.yaml"
reject 'secretKeyRef:|name: GREPNEST_DATABASE_URL|name: GREPNEST_(USER|ADMIN)_TOKEN' "$tmp/zoekt.yaml"
require 'name: GREPNEST_DATABASE_URL' "$tmp/indexer.yaml"
reject 'name: GREPNEST_(USER|ADMIN)_TOKEN' "$tmp/indexer.yaml"

sed -n '/^# Source: grepnest\/templates\/ingress.yaml$/,/^---$/p' \
  "$tmp/optional.yaml" >"$tmp/optional-ingress.yaml"
require '^kind: Ingress$' "$tmp/optional-ingress.yaml"
reject 'pilot-grepnest-zoekt|name: .*zoekt|backend:.*zoekt' "$tmp/optional-ingress.yaml"
reject 'host: "?\*|path: /\*|host: "?default([.]|"|$)' "$tmp/optional-ingress.yaml"

policies='deny-ingress allow-server-ingress allow-zoekt-ingress allow-indexer-metrics-ingress deny-egress allow-zoekt-egress allow-graph-egress allow-dns-egress allow-postgresql-egress allow-github-egress allow-identity-provider-egress'
for policy in $policies; do
  sed -n "/^  name: pilot-grepnest-$policy\$/,/^---\$/p" \
    "$tmp/optional.yaml" >"$tmp/$policy.yaml"
  require "^  name: pilot-grepnest-$policy\$" "$tmp/$policy.yaml"
  sed -n '/^spec:$/,/^---$/p' "$tmp/$policy.yaml" >"$tmp/$policy-spec.yaml"
  require '^spec:$' "$tmp/$policy-spec.yaml"
  require 'app.kubernetes.io/name: grepnest' "$tmp/$policy-spec.yaml"
  require 'app.kubernetes.io/instance: pilot' "$tmp/$policy-spec.yaml"
done

require 'policyTypes: \[Ingress\]' "$tmp/deny-ingress-spec.yaml"
require 'ingress: \[\]' "$tmp/deny-ingress-spec.yaml"
require 'app.kubernetes.io/component: server' "$tmp/allow-server-ingress-spec.yaml"
require 'policyTypes: \[Ingress\]' "$tmp/allow-server-ingress-spec.yaml"
for peer in grepnest ingress-nginx monitoring; do
  require "kubernetes.io/metadata.name: $peer" "$tmp/allow-server-ingress-spec.yaml"
done
require 'protocol: TCP, port: 8080' "$tmp/allow-server-ingress-spec.yaml"

require 'app.kubernetes.io/component: node' "$tmp/allow-zoekt-ingress-spec.yaml"
require 'policyTypes: \[Ingress\]' "$tmp/allow-zoekt-ingress-spec.yaml"
require '^        - namespaceSelector:$' "$tmp/allow-zoekt-ingress-spec.yaml"
require '^          podSelector:$' "$tmp/allow-zoekt-ingress-spec.yaml"
require 'app.kubernetes.io/component: server' "$tmp/allow-zoekt-ingress-spec.yaml"
[ "$(grep -E -c -e 'app.kubernetes.io/component: node' "$tmp/allow-zoekt-ingress-spec.yaml")" -eq 2 ] || exit 1
require 'protocol: TCP, port: 6070' "$tmp/allow-zoekt-ingress-spec.yaml"

require 'app.kubernetes.io/component: node' "$tmp/allow-indexer-metrics-ingress-spec.yaml"
require 'policyTypes: \[Ingress\]' "$tmp/allow-indexer-metrics-ingress-spec.yaml"
require 'kubernetes.io/metadata.name: monitoring' "$tmp/allow-indexer-metrics-ingress-spec.yaml"
require 'protocol: TCP, port: 9090' "$tmp/allow-indexer-metrics-ingress-spec.yaml"

require 'policyTypes: \[Egress\]' "$tmp/deny-egress-spec.yaml"
require 'egress: \[\]' "$tmp/deny-egress-spec.yaml"
require 'values: \[server, node\]' "$tmp/allow-zoekt-egress-spec.yaml"
require 'policyTypes: \[Egress\]' "$tmp/allow-zoekt-egress-spec.yaml"
require 'app.kubernetes.io/component: node' "$tmp/allow-zoekt-egress-spec.yaml"
require 'protocol: TCP, port: 6070' "$tmp/allow-zoekt-egress-spec.yaml"
reject 'port: 8081' "$tmp/allow-zoekt-egress-spec.yaml"
require 'app.kubernetes.io/component: server' "$tmp/allow-graph-egress-spec.yaml"
reject 'matchExpressions:|values:' "$tmp/allow-graph-egress-spec.yaml"
[ "$(grep -E -c -e 'app.kubernetes.io/component: node' "$tmp/allow-graph-egress-spec.yaml")" -eq 1 ] || exit 1
require 'policyTypes: \[Egress\]' "$tmp/allow-graph-egress-spec.yaml"
require 'protocol: TCP, port: 8081' "$tmp/allow-graph-egress-spec.yaml"

require 'policyTypes: \[Egress\]' "$tmp/allow-dns-egress-spec.yaml"
require '^        - namespaceSelector:$' "$tmp/allow-dns-egress-spec.yaml"
require '^          podSelector:$' "$tmp/allow-dns-egress-spec.yaml"
require 'kubernetes.io/metadata.name: kube-system' "$tmp/allow-dns-egress-spec.yaml"
require 'k8s-app: kube-dns' "$tmp/allow-dns-egress-spec.yaml"
require 'protocol: UDP, port: 53' "$tmp/allow-dns-egress-spec.yaml"
require 'protocol: TCP, port: 53' "$tmp/allow-dns-egress-spec.yaml"

require 'values: \[server, node, migration, graph, scanner\]' "$tmp/allow-postgresql-egress-spec.yaml"
require 'policyTypes: \[Egress\]' "$tmp/allow-postgresql-egress-spec.yaml"
require 'cidr: "192\.0\.2\.10/32"' "$tmp/allow-postgresql-egress-spec.yaml"
require 'protocol: TCP, port: 5432' "$tmp/allow-postgresql-egress-spec.yaml"
require 'values: \[server, node, scanner\]' "$tmp/allow-github-egress-spec.yaml"
require 'policyTypes: \[Egress\]' "$tmp/allow-github-egress-spec.yaml"
require 'cidr: "198\.51\.100\.0/24"' "$tmp/allow-github-egress-spec.yaml"
require 'cidr: "2001:db8:1234::/48"' "$tmp/allow-github-egress-spec.yaml"
require 'protocol: TCP, port: 443' "$tmp/allow-github-egress-spec.yaml"
require 'app.kubernetes.io/component: server' "$tmp/allow-identity-provider-egress-spec.yaml"
require 'cidr: "203\.0\.113\.10/32"' "$tmp/allow-identity-provider-egress-spec.yaml"
require 'protocol: TCP, port: 443' "$tmp/allow-identity-provider-egress-spec.yaml"
require 'mountPath: /var/run/secrets/grepnest/oidc/client-secret' "$tmp/optional.yaml"
require 'secretName: grepnest-oidc' "$tmp/optional.yaml"
reject 'GREPNEST_OIDC_CLIENT_SECRET: ' "$tmp/optional.yaml"
require 'GREPNEST_OAUTH_GITHUB_CLIENT_ID: "grepnest-github"' "$tmp/github-oauth.yaml"
require 'GREPNEST_OAUTH_GITHUB_CLIENT_SECRET_FILE: /var/run/secrets/grepnest/oauth-github/client-secret' "$tmp/github-oauth.yaml"
require 'mountPath: /var/run/secrets/grepnest/oauth-github/client-secret' "$tmp/github-oauth.yaml"
require 'secretName: grepnest-github-oauth' "$tmp/github-oauth.yaml"
require 'readOnly: true' "$tmp/github-oauth.yaml"
reject 'GREPNEST_OAUTH_GITHUB_(CA|CLIENT_SECRET):|oauth-github-ca|allow-github-oauth' "$tmp/github-oauth.yaml"
for key in GREPNEST_SSO_SESSION_IDLE GREPNEST_SSO_SESSION_TTL GREPNEST_SSO_LOGIN_FLOW_TTL; do
  [ "$(grep -E -c -e "^  $key:" "$tmp/optional.yaml")" -eq 1 ] || exit 1
done
require 'GREPNEST_SCIM_TOKEN_FILE: /var/run/secrets/grepnest/scim/token' "$tmp/optional.yaml"
require 'mountPath: /var/run/secrets/grepnest/scim/token' "$tmp/optional.yaml"
require 'secretName: grepnest-scim' "$tmp/optional.yaml"
reject 'GREPNEST_SCIM_TOKEN:|GREPNEST_SCIM_TOKEN_FILE:' "$tmp/minimal.yaml"
reject '^kind: Secret$|GREPNEST_SCIM_TOKEN: ' "$tmp/optional.yaml"
require 'GREPNEST_PUBLIC_URL: "https://grepnest.example.invalid"' "$tmp/scim.yaml"
require 'GREPNEST_SCIM_TOKEN_FILE: /var/run/secrets/grepnest/scim/token' "$tmp/scim.yaml"
reject 'GREPNEST_OIDC_' "$tmp/scim.yaml"
reject 'GREPNEST_(USER|ADMIN)_(TOKEN|INSTALLATION_ID|REPOSITORY_IDS)' "$tmp/minimal.yaml"
reject 'GREPNEST_BREAK_GLASS_ENABLED|BREAK_GLASS.*(PASSWORD|HASH|SALT)' "$tmp/minimal.yaml"
require 'GREPNEST_BREAK_GLASS_ENABLED: "true"' "$tmp/break-glass.yaml"
require 'GREPNEST_BREAK_GLASS_ENABLED: "true"' "$tmp/github-break-glass.yaml"
reject 'BREAK_GLASS.*(PASSWORD|HASH|SALT)|^kind: Secret$' "$tmp/break-glass.yaml"
expect_failure "$tmp/break-glass-type.err" helm template bad "$chart" -f "$minimal" \
  --set-string=breakGlass.enabled=true
expect_failure "$tmp/break-glass-without-oidc.err" helm template bad "$chart" -f "$minimal" \
  --set=breakGlass.enabled=true

expect_failure "$tmp/github-oauth-client-id.err" helm template bad "$chart" -f "$minimal" \
  --set=server.sso.githubOAuth.enabled=true \
  --set-string=secrets.githubOAuth.name=grepnest-github-oauth \
  --set-string=server.sso.publicURL=https://grepnest.example.invalid
expect_failure "$tmp/github-oauth-secret.err" helm template bad "$chart" -f "$minimal" \
  --set=server.sso.githubOAuth.enabled=true \
  --set-string=server.sso.githubOAuth.clientID=grepnest-github \
  --set-string=server.sso.publicURL=https://grepnest.example.invalid
expect_failure "$tmp/github-oauth-public-url.err" helm template bad "$chart" -f "$minimal" \
  --set=server.sso.githubOAuth.enabled=true \
  --set-string=server.sso.githubOAuth.clientID=grepnest-github \
  --set-string=secrets.githubOAuth.name=grepnest-github-oauth \
  --set-string=server.sso.publicURL=http://grepnest.example.invalid
expect_failure "$tmp/github-oauth-enabled-type.err" helm template bad "$chart" -f "$minimal" \
  --set-string=server.sso.githubOAuth.enabled=true

expect_failure "$tmp/scim-secret.err" helm template bad "$chart" -f "$minimal" \
  --set=server.scim.enabled=true
expect_failure "$tmp/scim-public-url.err" helm template bad "$chart" -f "$minimal" \
  --set=server.scim.enabled=true --set-string=secrets.scim.name=grepnest-scim \
  --set-string=server.sso.publicURL=http://grepnest.example.invalid

reject '^ *- \{\}|^ *from: *\[?\]?$|^ *to: *\[?\]?$|^ *- (podSelector|namespaceSelector): *\{\}$' "$tmp/optional.yaml"
reject 'cidr: "?(0\.0\.0\.0/0|::/0)"?' "$tmp/optional.yaml"
reject '^ *namespaceSelector: *\{\}$|^ *podSelector: *\{\}$' "$tmp/optional.yaml"

for manifest in "$tmp/graph-embedded.yaml" "$tmp/graph-separate.yaml"; do
  require 'GREPNEST_GRAPH_URL: "http://pilot-grepnest-graph:8081"' "$manifest"
  [ "$(grep -E -c -e 'name: graph-secret-runtime, mountPath: /var/run/secrets/grepnest/graph, readOnly: true' "$manifest")" -eq 2 ] || exit 1
  [ "$(grep -E -c -e '^      initContainers:$' "$manifest")" -eq 2 ] || exit 1
  [ "$(grep -E -c -e 'name: stage-graph-secret' "$manifest")" -eq 2 ] || exit 1
  [ "$(grep -E -c -e 'command: \["/usr/local/bin/grepnest-graph"\]' "$manifest")" -ge 2 ] || exit 1
  [ "$(grep -E -c -e 'args: \["stage-secret", "/var/run/secrets/grepnest/graph-source/secret", "/var/run/secrets/grepnest/graph/secret"\]' "$manifest")" -eq 2 ] || exit 1
  reject 'command: \["/bin/sh"|umask 077|cp .*graph-source|chmod 600' "$manifest"
  # ADR-0006 requires arbitrary non-root UIDs with root group. With no
  # conflicting group override, projected root:root 0440 sources are readable.
  [ "$(grep -E -c -e 'defaultMode: 0440' "$manifest")" -eq 2 ] || exit 1
  reject 'runAsGroup:|fsGroup:' "$manifest"
  [ "$(grep -E -c -e 'name: graph-secret-runtime, emptyDir: \{\}' "$manifest")" -eq 2 ] || exit 1
  require '^kind: Service$' "$manifest"
  require '^  name: pilot-grepnest-graph$' "$manifest"
  reject 'type: (NodePort|LoadBalancer)' "$manifest"
  [ "$(grep -E -c -e 'GREPNEST_GRAPH_DATA_DIR' "$manifest")" -eq 1 ] || exit 1
  [ "$(grep -E -c -e 'mountPath: \"?/data/graph\"?' "$manifest")" -eq 1 ] || exit 1
done
for manifest in "$tmp/uid-embedded.yaml" "$tmp/uid-separate.yaml"; do
  [ "$(grep -E -c -e 'name: stage-graph-secret' "$manifest")" -eq 2 ] || exit 1
done
require 'runAsUser: 1001230000' "$tmp/uid-embedded.yaml"
require 'runAsUser: 1001230001' "$tmp/uid-embedded.yaml"
require 'runAsUser: 1001230002' "$tmp/uid-separate.yaml"
require 'runAsUser: 1001230003' "$tmp/uid-separate.yaml"
reject 'backend:.*graph|name: pilot-grepnest-graph' "$tmp/optional-ingress.yaml"

require 'GREPNEST_GRAPH_MODE: "embedded"' "$tmp/graph-embedded.yaml"
require 'name: graph, containerPort: 8081' "$tmp/graph-embedded.yaml"
require 'mountPath: "/data/graph"' "$tmp/graph-embedded.yaml"
reject '^kind: Deployment$.*pilot-grepnest-graph|app.kubernetes.io/component: graph$' "$tmp/graph-embedded.yaml"
reject 'app.kubernetes.io/component: scanner$' "$tmp/minimal.yaml"

require 'GREPNEST_GRAPH_MODE: "separate"' "$tmp/graph-separate.yaml"
require '^# Source: grepnest/templates/graph.yaml$' "$tmp/graph-separate.yaml"
[ "$(grep -E -c -e '^kind: Deployment$' "$tmp/graph-separate.yaml")" -eq 3 ] || exit 1
for pattern in '^kind: PersistentVolumeClaim$' 'app.kubernetes.io/component: graph' \
  'command: \["/usr/local/bin/grepnest-graph"\]' \
  'httpGet: \{path: /healthz, port: graph\}' \
  'httpGet: \{path: /readyz, port: graph\}' \
  'automountServiceAccountToken: false' 'readOnlyRootFilesystem: true' \
  'runAsNonRoot: true' 'seccompProfile: \{type: RuntimeDefault\}'; do
  require "$pattern" "$tmp/graph-separate.yaml"
done

awk 'BEGIN {RS="---"} /kind: Deployment/ && /app.kubernetes.io\/component: graph/ {print}' \
  "$tmp/graph-separate.yaml" >"$tmp/graph-workload.yaml"
for pattern in 'grepnest.example.invalid/pool: graph' \
  'grepnest.example.invalid/tier' '^[[:space:]]*- graph$' \
  'grepnest.example.invalid/dedicated' 'value: graph'; do
  require "$pattern" "$tmp/graph-workload.yaml"
done

for pattern in 'app.kubernetes.io/component: scanner' '^  replicas: 3$' \
  'command: \["/usr/local/bin/grepnest-scanner"\]' \
  'name: worktree, mountPath: /data' 'name: worktree, emptyDir: \{\}' \
  'name: metrics, containerPort: 9090' 'requests:' 'limits:' \
  'automountServiceAccountToken: false' 'readOnlyRootFilesystem: true'; do
  require "$pattern" "$tmp/graph-separate.yaml"
done
awk 'BEGIN {RS="---"} /kind: Deployment/ && /app.kubernetes.io\/component: scanner/ {print}' \
  "$tmp/graph-separate.yaml" >"$tmp/scanner-workload.yaml"
for pattern in 'grepnest.example.invalid/pool: scanner' \
  'grepnest.example.invalid/tier' '^[[:space:]]*- scanner$' \
  'grepnest.example.invalid/dedicated' 'value: scanner'; do
  require "$pattern" "$tmp/scanner-workload.yaml"
done
require 'values: \[server, node\]' "$tmp/graph-separate.yaml"
require 'values: \[server, node, migration, graph, scanner\]' "$tmp/graph-separate.yaml"
require 'values: \[server, node, scanner\]' "$tmp/graph-separate.yaml"
[ "$(grep -E -c -e '^kind: ServiceMonitor$' "$tmp/graph-separate.yaml")" -eq 4 ] || exit 1

expect_failure "$tmp/repository.err" helm template bad "$chart" -f "$minimal" \
  --set-string=images.application.repository=
expect_failure "$tmp/digest.err" helm template bad "$chart" -f "$minimal" \
  --set=images.node.digest=latest
expect_failure "$tmp/scip-upload-min.err" helm template bad "$chart" -f "$minimal" \
  --set=server.config.scipMaxUploadBytes=0
expect_failure "$tmp/scip-upload-max.err" helm template bad "$chart" -f "$minimal" \
  --set=server.config.scipMaxUploadBytes=268435457
for field in nameOverride fullnameOverride; do
  for value in Bad bad_name -bad bad- \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; do
    output=$tmp/$field-$(printf '%s' "$value" | tr -c 'a-zA-Z0-9' _).err
    expect_failure "$output" helm template bad "$chart" -f "$minimal" \
      --set-string="$field=$value"
    require "/$field" "$output"
  done
done
expect_failure "$tmp/runtime-secret-name.err" helm template bad "$chart" -f "$minimal" \
  --set-string='secrets.runtime.name=bad name'
expect_failure "$tmp/runtime-secret-key.err" helm template bad "$chart" -f "$minimal" \
  --set-string='secrets.runtime.databaseURLKey=bad/key'
expect_failure "$tmp/ingress-class-name.err" helm template bad "$chart" -f "$minimal" -f "$optional" \
  --set-string=ingress.className= --set=monitoring.serviceMonitor.enabled=false
expect_failure "$tmp/crd.err" helm template bad "$chart" -f "$minimal" -f "$optional"
expect_failure "$tmp/ipv4.err" helm template bad "$chart" -f "$minimal" \
  --set-json='networkPolicy.externalEgress.postgresql.cidrs=[{"address":"999.0.2.1","prefix":32}]'
expect_failure "$tmp/ipv6.err" helm template bad "$chart" -f "$minimal" \
  --set-json='networkPolicy.externalEgress.github.cidrs=[{"address":"2001:db8::zz","prefix":64}]'
expect_failure "$tmp/ipv4-prefix.err" helm template bad "$chart" -f "$minimal" \
  --set-json='networkPolicy.externalEgress.postgresql.cidrs=[{"address":"192.0.2.1","prefix":0}]'
expect_failure "$tmp/ipv6-prefix.err" helm template bad "$chart" -f "$minimal" \
  --set-json='networkPolicy.externalEgress.github.cidrs=[{"address":"2001:db8::1","prefix":0}]'
expect_failure "$tmp/optional-selector.err" helm template bad "$chart" -f "$minimal" -f "$optional" \
  --set-json='networkPolicy.serverIngress.ingressControllerNamespaceSelector.matchLabels=null'
expect_failure "$tmp/dns-selectors.err" helm template bad "$chart" -f "$minimal" \
  --set=networkPolicy.externalEgress.enabled=true \
  --set-json='networkPolicy.externalEgress.postgresql.cidrs=[{"address":"192.0.2.1","prefix":32}]' \
  --set-json='networkPolicy.externalEgress.github.cidrs=[{"address":"2001:db8::1","prefix":128}]' \
  --set-json='networkPolicy.externalEgress.dns.namespaceSelector=null' \
  --set-json='networkPolicy.externalEgress.dns.podSelector=null'

require "/images/application/repository.*minLength: got 0, want 1" "$tmp/repository.err"
require "/images/node/digest.*'latest'.*does not match pattern" "$tmp/digest.err"
require '/server/config/scipMaxUploadBytes.*minimum: got 0, want 1' "$tmp/scip-upload-min.err"
require '/server/config/scipMaxUploadBytes.*maximum:' "$tmp/scip-upload-max.err"
require "/secrets/runtime/name.*'bad name'.*does not match pattern" "$tmp/runtime-secret-name.err"
require "/secrets/runtime/databaseURLKey.*'bad/key'.*does not match pattern" "$tmp/runtime-secret-key.err"
require '/ingress/className.*minLength: got 0, want 1' "$tmp/ingress-class-name.err"
require 'monitoring.serviceMonitor.enabled requires monitoring.coreos.com/v1/ServiceMonitor' "$tmp/crd.err"
require "/networkPolicy/externalEgress/postgresql/cidrs/0/address.*'999\.0\.2\.1'.*not valid ipv4" "$tmp/ipv4.err"
require "/networkPolicy/externalEgress/github/cidrs/0/address.*'2001:db8::zz'.*not valid ipv6" "$tmp/ipv6.err"
require '/networkPolicy/externalEgress/postgresql/cidrs/0/prefix.*minimum: got 0, want 1' "$tmp/ipv4-prefix.err"
require '/networkPolicy/externalEgress/github/cidrs/0/prefix.*minimum: got 0, want 1' "$tmp/ipv6-prefix.err"
require '/networkPolicy/serverIngress/ingressControllerNamespaceSelector/matchLabels.*got null, want object' "$tmp/optional-selector.err"
require "/networkPolicy/externalEgress/dns.*missing properties 'namespaceSelector', 'podSelector'" "$tmp/dns-selectors.err"

echo 'helm render tests passed'
