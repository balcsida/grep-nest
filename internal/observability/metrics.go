package observability

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry           *prometheus.Registry
	activeRequests     prometheus.Gauge
	httpRequests       *prometheus.CounterVec
	httpDuration       *prometheus.HistogramVec
	httpResponseSize   *prometheus.HistogramVec
	backendCalls       *prometheus.CounterVec
	backendDuration    *prometheus.HistogramVec
	githubRequests     *prometheus.CounterVec
	webhookDeliveries  *prometheus.CounterVec
	indexQueueDepth    *prometheus.GaugeVec
	indexPhases        *prometheus.CounterVec
	indexDuration      *prometheus.HistogramVec
	graphQueueDepth    *prometheus.GaugeVec
	graphPhases        *prometheus.CounterVec
	graphDuration      *prometheus.HistogramVec
	graphQueries       *prometheus.CounterVec
	graphQueryDuration *prometheus.HistogramVec
	graphSyncs         *prometheus.CounterVec
	graphSyncDuration  *prometheus.HistogramVec
	graphReady         prometheus.Gauge
	authEvents         *prometheus.CounterVec
}

func New() *Metrics {
	metrics := &Metrics{registry: prometheus.NewRegistry()}
	metrics.activeRequests = prometheus.NewGauge(prometheus.GaugeOpts{Name: "grepnest_http_active_requests", Help: "Active HTTP requests."})
	metrics.httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_http_requests_total", Help: "HTTP requests."}, []string{"method", "path", "status"})
	metrics.httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "grepnest_http_request_duration_seconds", Help: "HTTP request duration."}, []string{"method", "path", "status"})
	metrics.httpResponseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "grepnest_http_response_size_bytes", Help: "HTTP response size."}, []string{"method", "path", "status"})
	metrics.backendCalls = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_search_backend_calls_total", Help: "Search backend calls."}, []string{"result"})
	metrics.backendDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "grepnest_search_backend_duration_seconds", Help: "Search backend duration."}, []string{"result"})
	metrics.githubRequests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_github_requests_total", Help: "GitHub API requests."}, []string{"operation", "result"})
	metrics.webhookDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_webhook_deliveries_total", Help: "GitHub webhook deliveries."}, []string{"event", "result"})
	metrics.indexQueueDepth = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "grepnest_index_queue_depth", Help: "Index queue jobs."}, []string{"state"})
	metrics.indexPhases = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_index_phase_total", Help: "Index phase executions."}, []string{"phase", "result"})
	metrics.indexDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "grepnest_index_phase_duration_seconds", Help: "Index phase duration."}, []string{"phase", "result"})
	metrics.graphQueueDepth = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "grepnest_graph_queue_depth", Help: "Graph scan queue jobs."}, []string{"state"})
	metrics.graphPhases = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_graph_scan_phase_total", Help: "Graph scan phase executions."}, []string{"phase", "result"})
	metrics.graphDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "grepnest_graph_scan_phase_duration_seconds", Help: "Graph scan phase duration."}, []string{"phase", "result"})
	metrics.graphQueries = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_graph_query_total", Help: "Graph queries."}, []string{"operation", "result"})
	metrics.graphQueryDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "grepnest_graph_query_duration_seconds", Help: "Graph query duration."}, []string{"operation", "result"})
	metrics.graphSyncs = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_graph_sync_total", Help: "Graph synchronizations."}, []string{"result"})
	metrics.graphSyncDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "grepnest_graph_sync_duration_seconds", Help: "Graph synchronization duration."}, []string{"result"})
	metrics.graphReady = prometheus.NewGauge(prometheus.GaugeOpts{Name: "grepnest_graph_ready", Help: "Graph readiness."})
	metrics.authEvents = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "grepnest_auth_events_total", Help: "Authentication events."}, []string{"provider", "event", "result"})
	metrics.registry.MustRegister(metrics.activeRequests, metrics.httpRequests, metrics.httpDuration, metrics.httpResponseSize, metrics.backendCalls, metrics.backendDuration, metrics.githubRequests, metrics.webhookDeliveries, metrics.indexQueueDepth, metrics.indexPhases, metrics.indexDuration, metrics.graphQueueDepth, metrics.graphPhases, metrics.graphDuration, metrics.graphQueries, metrics.graphQueryDuration, metrics.graphSyncs, metrics.graphSyncDuration, metrics.graphReady, metrics.authEvents)
	return metrics
}

func (metrics *Metrics) ObserveGraphQuery(operation, result string, duration time.Duration) {
	labels := []string{fixed(operation, "context", "impact", "trace", "cypher"), successOrError(result)}
	metrics.graphQueries.WithLabelValues(labels...).Inc()
	metrics.graphQueryDuration.WithLabelValues(labels...).Observe(duration.Seconds())
}

func (metrics *Metrics) ObserveGraphSync(result string, duration time.Duration) {
	result = successOrError(result)
	metrics.graphSyncs.WithLabelValues(result).Inc()
	metrics.graphSyncDuration.WithLabelValues(result).Observe(duration.Seconds())
}

func (metrics *Metrics) SetGraphReady(ready bool) {
	if ready {
		metrics.graphReady.Set(1)
		return
	}
	metrics.graphReady.Set(0)
}

func (metrics *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{})
}

func (metrics *Metrics) WrapHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		metrics.activeRequests.Inc()
		defer metrics.activeRequests.Dec()
		started := time.Now()
		recorded := &responseWriter{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(recorded, request)
		labels := []string{request.Method, routePattern(request), strconv.Itoa(recorded.status)}
		metrics.httpRequests.WithLabelValues(labels...).Inc()
		metrics.httpDuration.WithLabelValues(labels...).Observe(time.Since(started).Seconds())
		metrics.httpResponseSize.WithLabelValues(labels...).Observe(float64(recorded.bytes))
	})
}

func routePattern(request *http.Request) string {
	pattern := request.Pattern
	if _, path, ok := strings.Cut(pattern, " "); ok {
		pattern = path
	}
	if pattern == "" {
		return "unknown"
	}
	return pattern
}

func (metrics *Metrics) ObserveBackend(duration time.Duration, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	metrics.backendCalls.WithLabelValues(result).Inc()
	metrics.backendDuration.WithLabelValues(result).Observe(duration.Seconds())
}

func (metrics *Metrics) ObserveGitHub(operation, result string) {
	metrics.githubRequests.WithLabelValues(fixed(operation, "installation_token", "installations", "repositories", "default_branch", "contents", "dependency_sbom"), successOrError(result)).Inc()
}

func (metrics *Metrics) ObserveWebhook(event, result string) {
	metrics.webhookDeliveries.WithLabelValues(fixed(event, "push", "installation", "installation_repositories", "repository"), webhookResult(result)).Inc()
}

func (metrics *Metrics) SetQueueDepth(state string, depth int64) {
	metrics.indexQueueDepth.WithLabelValues(fixed(state, "queued", "running", "succeeded", "failed", "superseded")).Set(float64(depth))
}

func (metrics *Metrics) ObserveIndexPhase(phase, result string, duration time.Duration) {
	labels := []string{fixed(phase, "fetch", "index", "visibility"), successOrError(result)}
	metrics.indexPhases.WithLabelValues(labels...).Inc()
	metrics.indexDuration.WithLabelValues(labels...).Observe(duration.Seconds())
}

func (metrics *Metrics) SetGraphQueueDepth(state string, depth int64) {
	state = fixed(state, "queued", "running", "succeeded", "failed", "superseded")
	if state == "unknown" {
		return
	}
	metrics.graphQueueDepth.WithLabelValues(state).Set(float64(depth))
}

func (metrics *Metrics) ObserveGraphPhase(phase, result string, duration time.Duration) {
	phase = fixed(phase, "token", "checkout", "scan", "publish")
	if phase == "unknown" {
		return
	}
	labels := []string{phase, successOrError(result)}
	metrics.graphPhases.WithLabelValues(labels...).Inc()
	metrics.graphDuration.WithLabelValues(labels...).Observe(duration.Seconds())
}

func (metrics *Metrics) ObserveAuth(provider, event, result string) {
	metrics.authEvents.WithLabelValues(fixed(provider, "oidc", "oauth", "session", "static"), fixed(event, "login_start", "callback", "session_auth", "logout", "cleanup"), authResult(result)).Inc()
}

func authResult(result string) string {
	for _, candidate := range []string{"success", "invalid", "denied", "error"} {
		if result == candidate {
			return result
		}
	}
	return "error"
}

func fixed(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}

func successOrError(result string) string {
	if result == "success" {
		return result
	}
	return "error"
}

func webhookResult(result string) string {
	for _, candidate := range []string{"accepted", "ignored", "duplicate", "error"} {
		if result == candidate {
			return result
		}
	}
	return "error"
}

type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (writer *responseWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

func (writer *responseWriter) WriteHeader(status int) {
	if writer.wrote {
		return
	}
	writer.wrote = true
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *responseWriter) Write(body []byte) (int, error) {
	if !writer.wrote {
		writer.WriteHeader(http.StatusOK)
	}
	count, err := writer.ResponseWriter.Write(body)
	writer.bytes += count
	return count, err
}
