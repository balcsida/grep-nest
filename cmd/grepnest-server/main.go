package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/grepnest/grepnest/internal/account"
	"github.com/grepnest/grepnest/internal/admin"
	"github.com/grepnest/grepnest/internal/audit"
	"github.com/grepnest/grepnest/internal/authn"
	"github.com/grepnest/grepnest/internal/authz"
	"github.com/grepnest/grepnest/internal/config"
	"github.com/grepnest/grepnest/internal/githubapp"
	"github.com/grepnest/grepnest/internal/graphclient"
	"github.com/grepnest/grepnest/internal/graphingest"
	"github.com/grepnest/grepnest/internal/graphservice"
	"github.com/grepnest/grepnest/internal/httpapi"
	"github.com/grepnest/grepnest/internal/mcpserver"
	"github.com/grepnest/grepnest/internal/observability"
	"github.com/grepnest/grepnest/internal/postgres"
	"github.com/grepnest/grepnest/internal/repository"
	"github.com/grepnest/grepnest/internal/scim"
	"github.com/grepnest/grepnest/internal/scipgraph"
	"github.com/grepnest/grepnest/internal/search"
	"github.com/grepnest/grepnest/internal/sso"
	"github.com/grepnest/grepnest/internal/sso/oidc"
	"github.com/grepnest/grepnest/internal/webhook"
	"github.com/grepnest/grepnest/internal/webui"
	"github.com/grepnest/grepnest/internal/zoekt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	searchNodeID             = "primary"
	reconcileInterval        = 5 * time.Minute
	maxPrivateKeyBytes       = 64 << 10
	maxWebhookKeyBytes       = 64 << 10
	maxCABytes               = 1 << 20
	maxOIDCClientSecretBytes = 64 << 10
	maxOIDCCABytes           = 1 << 20
	maxSCIMTokenBytes        = 64 << 10
	maxGitHubResponseBytes   = 2 << 20
)

func main() { os.Exit(run()) }

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	settings, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		return 1
	}
	handler, closeRuntime, err := newRuntime(ctx, settings, logger)
	if err != nil {
		logger.Error("server setup failed", "error", err)
		return 1
	}
	defer closeRuntime()
	server := newHTTPServer(settings.ListenAddress, handler)
	logger.Info("server listening", "address", settings.ListenAddress)
	if err := serveHTTP(ctx, server, logger); err != nil {
		logger.Error("server listen failed", "error", err)
		return 1
	}
	return 0
}

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: address, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute,
	}
}

type shutdownServer interface {
	ListenAndServe() error
	Shutdown(context.Context) error
}

func serveHTTP(ctx context.Context, server shutdownServer, logger *slog.Logger) error {
	listenDone := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				logger.Error("server shutdown failed", "error", err)
			}
		case <-listenDone:
		}
	}()
	err := server.ListenAndServe()
	close(listenDone)
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func newHandler(settings config.Config) (http.Handler, error) {
	if settings.DatabaseURL != "" {
		return nil, errors.New("durable server requires a runtime context")
	}
	metrics := observability.New()
	registry, err := repository.Load(settings.RepositoriesFile, settings.Limits.MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	// Neither principal sets Administrator: an administrator principal routes
	// reads through Static.AnyAuthorizedRepository, which ignores scope and
	// would expose every entry in the registry file.
	authenticator := authn.NewStatic(map[string]authn.Principal{
		settings.UserToken:  {Subject: "user", Method: "bearer", RepositoryIDs: staticRepositoryIDs(registry, settings.UserRepositories), RepositoryNames: settings.UserRepositories},
		settings.AdminToken: {Subject: "admin", Method: "bearer", RepositoryIDs: staticRepositoryIDs(registry, settings.AdminRepositories), RepositoryNames: settings.AdminRepositories},
	})
	backend, err := zoekt.New(settings.ZoektURL, http.DefaultClient, settings.Limits.MaxResponseBytes, metrics)
	if err != nil {
		return nil, err
	}
	service := search.NewService(backend, authz.NewStatic(registry), search.Limits{
		DefaultResults: settings.Limits.DefaultResults, MaxResults: settings.Limits.MaxResults,
		DefaultContextLines: settings.Limits.DefaultContextLines, MaxContextLines: settings.Limits.MaxContextLines,
		DefaultTimeout: settings.Limits.DefaultTimeout, MaxTimeout: settings.Limits.MaxTimeout,
		MaxResponseBytes: settings.Limits.MaxResponseBytes,
	})
	return newAPIHandler(settings, metrics, authn.RequestAuthenticator{Bearer: authenticator, Metrics: metrics}, service, &repository.Service{Store: registry}, nil, nil, nil, nil, nil, nil, backend, nil, nil, nil, nil), nil
}

func staticRepositoryIDs(registry repository.Registry, names []string) []int64 {
	var ids []int64
	for _, candidate := range registry.Repositories() {
		if slices.Contains(names, candidate.Name) {
			if candidate.GitHubID != 0 {
				ids = append(ids, candidate.GitHubID)
			} else {
				ids = append(ids, candidate.ID)
			}
		}
	}
	return ids
}

type authRuntime struct {
	requestAuth authn.RequestAuthenticator
	sessions    *authn.SessionManager
	providers   []sso.Provider
}

func newAuthRuntime(ctx context.Context, settings config.Config, store authn.SessionStore, bearer authn.Authenticator, metrics *observability.Metrics) (*authRuntime, error) {
	runtime := &authRuntime{requestAuth: authn.RequestAuthenticator{Bearer: bearer, Metrics: metrics}}
	if !settings.SSO.OIDC.Enabled {
		return runtime, nil
	}
	secret, err := readBoundedRegularFile(settings.SSO.OIDC.ClientSecretFile, maxOIDCClientSecretBytes)
	if err != nil {
		return nil, fmt.Errorf("read OIDC client secret: %w", err)
	}
	var caPEM []byte
	if settings.SSO.OIDC.CAFile != "" {
		caPEM, err = readBoundedRegularFile(settings.SSO.OIDC.CAFile, maxOIDCCABytes)
		if err != nil {
			return nil, fmt.Errorf("read OIDC CA: %w", err)
		}
	}
	client, err := oidc.New(ctx, settings.SSO.OIDC, settings.SSO.PublicURL, secret, caPEM)
	if err != nil {
		return nil, err
	}
	runtime.sessions = &authn.SessionManager{Store: store, IdleTTL: settings.SSO.SessionIdle, TTL: settings.SSO.SessionTTL}
	if recorder, ok := store.(audit.Recorder); ok {
		runtime.sessions.Audit = recorder
	}
	runtime.requestAuth.Session = runtime.sessions
	runtime.requestAuth.PublicOrigin = settings.SSO.PublicURL.Scheme + "://" + settings.SSO.PublicURL.Host
	provider := &oidc.Provider{Client: client, Store: store, Sessions: runtime.sessions, LoginTTL: settings.SSO.LoginFlowTTL}
	if recorder, ok := store.(audit.Recorder); ok {
		provider.Audit = recorder
	}
	runtime.providers = []sso.Provider{provider}
	return runtime, nil
}

func newRuntime(ctx context.Context, settings config.Config, logger *slog.Logger) (http.Handler, func(), error) {
	if settings.DatabaseURL == "" {
		handler, err := newHandler(settings)
		return handler, func() {}, err
	}
	return newDurableRuntime(ctx, settings, logger)
}

func newDurableRuntime(ctx context.Context, settings config.Config, logger *slog.Logger) (http.Handler, func(), error) {
	privateKey, err := readBoundedFile(settings.GitHub.PrivateKeyFile, maxPrivateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read GitHub private key: %w", err)
	}
	webhookSecret, err := readBoundedFile(settings.GitHub.WebhookSecretFile, maxWebhookKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read GitHub webhook secret: %w", err)
	}
	var caPEM []byte
	if settings.GitHub.CAFile != "" {
		caPEM, err = readBoundedFile(settings.GitHub.CAFile, maxCABytes)
		if err != nil {
			return nil, nil, fmt.Errorf("read GitHub CA: %w", err)
		}
	}
	endpoints, err := githubEndpoints(settings.GitHub)
	if err != nil {
		return nil, nil, err
	}
	httpClient, err := githubapp.NewHTTPClient(caPEM, endpoints, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	signer, err := githubapp.NewSigner(settings.GitHub.AppID, privateKey, nil)
	if err != nil {
		return nil, nil, err
	}
	pool, err := postgres.Open(ctx, settings.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (http.Handler, func(), error) {
		pool.Close()
		return nil, nil, err
	}
	if err := postgres.Migrate(ctx, pool); err != nil {
		return fail(err)
	}
	graphClient, err := graphclient.New(settings.Graph.URL, settings.Graph.InternalSecret, http.DefaultClient, settings.Graph.MaxResponseBytes)
	if err != nil {
		return fail(err)
	}
	metrics := observability.New()
	store := postgres.New(pool)
	if err := store.UpsertSearchNode(ctx, searchNodeID, settings.ZoektURL); err != nil {
		return fail(err)
	}
	githubClient := githubapp.NewClient(endpoints, httpClient, signer, settings.GitHub.APIVersion, maxGitHubResponseBytes, nil, metrics)
	reconciler := githubapp.NewReconciler(githubClient, store)
	loopCtx, cancel := context.WithCancel(ctx)
	done, err := startPeriodic(loopCtx, reconcileInterval, reconciler.All, func(ctx context.Context) error {
		return refreshQueueDepths(ctx, store, metrics)
	}, func(ctx context.Context) error {
		_, _, err := store.DeleteExpiredAuth(ctx, time.Now())
		return err
	}, func(error) { logger.Error("durable background refresh failed") })
	if err != nil {
		cancel()
		return fail(err)
	}
	reconcileRequests := make(chan int64, 64)
	reconcileDone := startReconcileRequests(loopCtx, reconcileRequests, reconciler.Installation, func(error) {
		logger.Error("webhook reconciliation failed")
	})
	backend, err := zoekt.New(settings.ZoektURL, http.DefaultClient, settings.Limits.MaxResponseBytes, metrics)
	if err != nil {
		cancel()
		<-done
		<-reconcileDone
		return fail(err)
	}
	authenticator := durableAuthenticator(store)
	auth, err := newAuthRuntime(loopCtx, settings, store, authenticator, metrics)
	if err != nil {
		cancel()
		<-done
		<-reconcileDone
		return fail(err)
	}
	var localAuth *authn.LocalAuthenticator
	if settings.SSO.BreakGlass {
		local, err := authn.NewLocalAuthenticator(store, auth.sessions, nil)
		if err != nil {
			cancel()
			<-done
			<-reconcileDone
			return fail(err)
		}
		local.Audit = store
		localAuth = &local
	}
	provisioning, scimService, err := newProvisioningRuntime(settings, store)
	if err != nil {
		cancel()
		<-done
		<-reconcileDone
		return fail(err)
	}
	searchService := search.NewService(backend, authz.NewPostgres(store), searchLimits(settings))
	repositoryService := &repository.Service{Store: store, GitHub: githubClient, SCIP: store}
	scipService := &scipgraph.Service{Store: store, GitHub: githubClient, MaxResults: settings.Limits.MaxResults}
	graphService := &graphingest.Service{Store: store}
	graphQueries := &graphservice.Service{Store: store, Backend: graphClient, Files: repositoryService, Limits: graphQueryLimits(settings.Graph), Observe: metrics.ObserveGraphQuery}
	processor := webhook.NewGitHubProcessor(store, reconcileRequests, metrics)
	adminService := &admin.Service{
		Store: store, Audit: store, GitHub: githubClient, ReconcileAll: reconciler.All,
		Config: admin.GitHubConfig{
			AppID: settings.GitHub.AppID, WebURL: settings.GitHub.WebURL, APIURL: settings.GitHub.APIURL,
			UploadURL: settings.GitHub.UploadURL, GitURL: settings.GitHub.GitURL, APIVersion: settings.GitHub.APIVersion,
			PrivateKeyConfigured: settings.GitHub.PrivateKeyFile != "", WebhookSecretConfigured: settings.GitHub.WebhookSecretFile != "",
			CAConfigured: settings.GitHub.CAFile != "",
		},
	}
	handler := newAPIHandler(settings, metrics, auth.requestAuth, searchService, repositoryService, scipService, graphService, graphQueries, webhookSecret, processor, adminService, durableReadiness{pool: pool, zoekt: backend}, auth.providers, auth.sessions, provisioning, scimService)
	if localAuth != nil {
		mux := http.NewServeMux()
		httpapi.RegisterLocalAuth(mux, auth.requestAuth.PublicOrigin, localAuth, store)
		mux.Handle("/", handler)
		handler = mux
	}
	return httpapi.RequestIDs(nil, handler), func() {
		cancel()
		<-done
		<-reconcileDone
		pool.Close()
	}, nil
}

func durableAuthenticator(store authn.APITokenStore) authn.Authenticator {
	manager := authn.TokenManager{Store: store}
	if recorder, ok := store.(audit.Recorder); ok {
		manager.Audit = recorder
	}
	return manager
}

func newAPIHandler(settings config.Config, metrics *observability.Metrics, authenticator authn.RequestAuthenticator, service *search.Service, repositories *repository.Service, scipGraph *scipgraph.Service, graph *graphingest.Service, graphQueries *graphservice.Service, webhookSecret []byte, processor webhook.Processor, adminService *admin.Service, checker httpapi.ReadyChecker, providers []sso.Provider, sessions *authn.SessionManager, provisioning *authn.ProvisioningAuthenticator, scimService *scim.Service) http.Handler {
	mux := http.NewServeMux()
	fileReads := repositories != nil && repositories.GitHub != nil
	httpapi.RegisterAuth(mux, true, settings.SSO.BreakGlass, fileReads, providers, authenticator, sessions, metrics)
	webui.RegisterWithBreakGlass(mux, settings.SSO.BreakGlass)
	httpapi.RegisterSystem(mux, checker, metrics.Handler())
	httpapi.RegisterSearch(mux, authenticator, service, settings.Limits.MaxRequestBytes, settings.Limits.MaxResponseBytes)
	if manager, ok := authenticator.Bearer.(authn.TokenManager); ok {
		if store, ok := manager.Store.(*postgres.Store); ok {
			httpapi.RegisterAccount(mux, authenticator, &account.Service{Manager: manager, Authorizer: authz.NewPostgres(store)}, settings.Limits.MaxRequestBytes, settings.Limits.MaxResponseBytes)
		}
	}
	if repositories != nil {
		httpapi.RegisterRepositoryInventory(mux, authenticator, repositories, settings.Limits.MaxResults, settings.Limits.MaxResponseBytes)
		if fileReads {
			httpapi.RegisterFileReads(mux, authenticator, repositories, settings.Limits.MaxRequestBytes, settings.Limits.MaxResponseBytes)
		}
	}
	if scipGraph != nil {
		httpapi.RegisterSCIP(mux, authenticator, scipGraph, settings.Limits.MaxRequestBytes, settings.Limits.SCIPMaxUploadBytes, settings.Limits.MaxResponseBytes)
	}
	if graph != nil {
		httpapi.RegisterGraphIngestion(mux, authenticator.Bearer, graph, settings.Limits.GraphMaxUploadBytes, settings.Limits.MaxResponseBytes)
	}
	if graphQueries != nil {
		httpapi.RegisterGraphQueries(mux, authenticator.Bearer, graphQueries, settings.Graph.MaxRequestBytes, settings.Graph.MaxResponseBytes)
	}
	if adminService != nil {
		httpapi.RegisterAdmin(mux, authenticator, adminService, settings.Limits.MaxResults, settings.Limits.MaxRequestBytes, settings.Limits.MaxResponseBytes)
	}
	if processor != nil {
		httpapi.RegisterGitHubWebhook(mux, webhookSecret, 1<<20, processor)
	}
	mcpServer := mcpserver.NewWithLimits(mcpserver.Services{Search: service, Repositories: repositories, SCIP: scipGraph, Graph: graphQueries}, mcpserver.Limits{
		MaxItems: settings.Limits.MaxResults, MaxOutputBytes: settings.Limits.MaxResponseBytes, GraphMaxOutputBytes: settings.Graph.MaxResponseBytes,
	})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, nil)
	mux.Handle("/mcp", httpapi.AuthenticateBearer(authenticator.Bearer, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, settings.Limits.MaxRequestBytes)
		mcpHandler.ServeHTTP(writer, request)
	})))
	var handler http.Handler = mux
	if provisioning != nil && scimService != nil {
		handler = httpapi.GuardSCIMV2(handler, *provisioning, scimService)
	}
	return httpapi.RequestIDs(nil, metrics.WrapHTTP(handler))
}

func graphQueryLimits(graph config.Graph) graphservice.Limits {
	return graphservice.Limits{
		PerCategory: graph.QueryLimits.PerCategory, DefaultImpactDepth: graph.QueryLimits.DefaultImpactDepth, MaxDepth: graph.QueryLimits.MaxDepth,
		DefaultTraceDepth: graph.QueryLimits.DefaultTraceDepth, MaxTraceDepth: graph.QueryLimits.MaxTraceDepth, MaxRows: graph.QueryLimits.MaxRows,
		MaxNodes: graph.QueryLimits.MaxNodes, MaxEdges: graph.QueryLimits.MaxEdges, MaxFanout: graph.QueryLimits.MaxFanout,
		MaxResponseBytes: int(graph.MaxResponseBytes),
	}
}

func newProvisioningRuntime(settings config.Config, store scim.Store) (*authn.ProvisioningAuthenticator, *scim.Service, error) {
	if !settings.SCIM.Enabled {
		return nil, nil, nil
	}
	secret, err := readBoundedRegularFile(settings.SCIM.TokenFile, maxSCIMTokenBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read SCIM token: %w", err)
	}
	authenticator, err := authn.NewProvisioningAuthenticator(secret)
	if err != nil {
		return nil, nil, err
	}
	origin := settings.SCIM.PublicURL.Scheme + "://" + settings.SCIM.PublicURL.Host
	service := &scim.Service{Store: store, BaseURL: origin, MaxResults: settings.Limits.MaxResults}
	if recorder, ok := store.(audit.Recorder); ok {
		service.Audit = recorder
	}
	return &authenticator, service, nil
}

func searchLimits(settings config.Config) search.Limits {
	return search.Limits{
		DefaultResults: settings.Limits.DefaultResults, MaxResults: settings.Limits.MaxResults,
		DefaultContextLines: settings.Limits.DefaultContextLines, MaxContextLines: settings.Limits.MaxContextLines,
		DefaultTimeout: settings.Limits.DefaultTimeout, MaxTimeout: settings.Limits.MaxTimeout,
		MaxResponseBytes: settings.Limits.MaxResponseBytes,
	}
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("file exceeds size limit")
	}
	if len(data) == 0 {
		return nil, errors.New("file is empty")
	}
	return data, nil
}

func readBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("file exceeds size limit")
	}
	if len(data) == 0 {
		return nil, errors.New("file is empty")
	}
	return data, nil
}

func startPeriodic(ctx context.Context, interval time.Duration, reconcile, refresh, cleanup func(context.Context) error, onError func(error)) (<-chan struct{}, error) {
	if err := reconcile(ctx); err != nil {
		return nil, err
	}
	if err := refresh(ctx); err != nil {
		return nil, err
	}
	if err := cleanup(ctx); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, operation := range []func(context.Context) error{reconcile, refresh, cleanup} {
					if err := operation(ctx); err != nil && onError != nil {
						onError(err)
					}
				}
			}
		}
	}()
	return done, nil
}

func startReconcileRequests(ctx context.Context, requests <-chan int64, reconcile func(context.Context, int64) error, onError func(error)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case installationID := <-requests:
				if err := reconcile(ctx, installationID); err != nil {
					onError(err)
				}
			}
		}
	}()
	return done
}

func refreshQueueDepths(ctx context.Context, store *postgres.Store, metrics *observability.Metrics) error {
	depths, err := store.QueueDepths(ctx)
	if err != nil {
		return err
	}
	for _, state := range []string{"queued", "running", "succeeded", "failed", "superseded"} {
		metrics.SetQueueDepth(state, depths[state])
	}
	return nil
}

func githubEndpoints(settings config.GitHub) (githubapp.Endpoints, error) {
	values := []string{settings.WebURL, settings.APIURL, settings.UploadURL, settings.GitURL}
	parsed := make([]*url.URL, len(values))
	for index, value := range values {
		var err error
		if parsed[index], err = url.Parse(value); err != nil {
			return githubapp.Endpoints{}, errors.New("invalid GitHub endpoint")
		}
	}
	return githubapp.Endpoints{Web: parsed[0], API: parsed[1], Upload: parsed[2], Git: parsed[3]}, nil
}

type durableReadiness struct {
	pool  interface{ Ping(context.Context) error }
	zoekt httpapi.ReadyChecker
}

func (checker durableReadiness) Health(ctx context.Context) error {
	if err := checker.pool.Ping(ctx); err != nil {
		return err
	}
	return checker.zoekt.Health(ctx)
}
