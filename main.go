// Command leproxy implements https reverse proxy with automatic Letsencrypt usage for multiple
// hostnames/backends
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	log2 "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mleku/lol/chk"
	"github.com/mleku/lol/log"
	"go-simpler.org/env"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

func main() {

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx); err != nil {
		log2.Fatal(err)
	}
}

type C struct {
	Addr  string `env:"REVERSE_LISTEN" usage:"address to listen at" default:":443"`
	Conf  string `env:"REVERSE_MAP" usage:"file with host/backend mapping" default:"~/.config/reverse/mapping.conf"`
	Cache string `env:"REVERSE_CACHE" usage:"path to directory to cache key and certificates" default:"~/.cache/reverse"`
	HSTS  bool   `env:"REVERSE_HSTS" usage:"add Strict-Transport-Security header" default:"false"`
	Email string `env:"REVERSE_EMAIL" usage:"contact email address presented to letsencrypt CA"`
	HTTP  string `env:"REVERSE_HTTP" usage:"optional address to serve http-to-https redirects and ACME http-01 challenge responses" default:":80"`

	RTo   time.Duration `env:"REVERSE_RTO" usage:"maximum duration before timing out read of the request" default:"1m"`
	WTo   time.Duration `env:"REVERSE_WTO" usage:"maximum duration before timing out write of the response" default:"5m"`
	Idle  time.Duration `env:"REVERSE_IDLE" usage:"how long idle connection is kept before closing (set rto, wto to 0 to use this)"`
	Certs []string      `env:"REVERSE_CERTS" usage:"certificates and the domain they match: eg: mleku.dev:/path/to/cert - this will indicate to load two, one with extension .key and one with .crt, each expected to be PEM encoded TLS private and public keys, respectively"`
}

// GetEnv checks if the first command line argument is "env" and returns
// whether the environment configuration should be printed.
//
// # Return Values
//
//   - requested: A boolean indicating true if the 'env' argument was
//     provided, false otherwise.
//
// # Expected Behaviour
//
// The function returns true when the first command line argument is "env"
// (case-insensitive), signalling that the environment configuration should be
// printed. Otherwise, it returns false.
func GetEnv() (requested bool) {
	if len(os.Args) > 1 {
		switch strings.ToLower(os.Args[1]) {
		case "env":
			requested = true
		}
	}
	return
}

// KV is a key/value pair.
type KV struct{ Key, Value string }

// KVSlice is a sortable slice of key/value pairs, designed for managing
// configuration data and enabling operations like merging and sorting based on
// keys.
type KVSlice []KV

func (kv KVSlice) Len() int           { return len(kv) }
func (kv KVSlice) Less(i, j int) bool { return kv[i].Key < kv[j].Key }
func (kv KVSlice) Swap(i, j int)      { kv[i], kv[j] = kv[j], kv[i] }

// Compose merges two KVSlice instances into a new slice where key-value pairs
// from the second slice override any duplicate keys from the first slice.
//
// # Parameters
//
//   - kv2: The second KVSlice whose entries will be merged with the receiver.
//
// # Return Values
//
//   - out: A new KVSlice containing all entries from both slices, with keys
//     from kv2 taking precedence over keys from the receiver.
//
// # Expected Behaviour
//
// The method returns a new KVSlice that combines the contents of the receiver
// and kv2. If any key exists in both slices, the value from kv2 is used. The
// resulting slice remains sorted by keys as per the KVSlice implementation.
func (kv KVSlice) Compose(kv2 KVSlice) (out KVSlice) {
	// duplicate the initial KVSlice
	for _, p := range kv {
		out = append(out, p)
	}
out:
	for i, p := range kv2 {
		for j, q := range out {
			// if the key is repeated, replace the value
			if p.Key == q.Key {
				out[j].Value = kv2[i].Value
				continue out
			}
		}
		out = append(out, p)
	}
	return
}

// EnvKV generates key/value pairs from a configuration object's struct tags
//
// # Parameters
//
//   - cfg: A configuration object whose struct fields are processed for env tags
//
// # Return Values
//
//   - m: A KVSlice containing key/value pairs derived from the config's env tags
//
// # Expected Behaviour
//
// Processes each field of the config object, extracting values tagged with
// "env" and converting them to strings. Skips fields without an "env" tag.
// Handles various value types including strings, integers, booleans, durations,
// and string slices by joining elements with commas.
func EnvKV(cfg any) (m KVSlice) {
	t := reflect.TypeOf(cfg)
	for i := 0; i < t.NumField(); i++ {
		k := t.Field(i).Tag.Get("env")
		v := reflect.ValueOf(cfg).Field(i).Interface()
		var val string
		switch v.(type) {
		case string:
			val = v.(string)
		case int, bool, time.Duration:
			val = fmt.Sprint(v)
		case []string:
			arr := v.([]string)
			if len(arr) > 0 {
				val = strings.Join(arr, ",")
			}
		}
		// this can happen with embedded structs
		if k == "" {
			continue
		}
		m = append(m, KV{k, val})
	}
	return
}

// PrintEnv outputs sorted environment key/value pairs from a configuration object
// to the provided writer
//
// # Parameters
//
//   - cfg: Pointer to the configuration object containing env tags
//
//   - printer: Destination for the output, typically an io.Writer implementation
//
// # Expected Behaviour
//
// Outputs each environment variable derived from the config's struct tags in
// sorted order, formatted as "key=value\n" to the specified writer
func PrintEnv(cfg *C, printer io.Writer) {
	kvs := EnvKV(*cfg)
	sort.Sort(kvs)
	for _, v := range kvs {
		_, _ = fmt.Fprintf(printer, "%s=%s\n", v.Key, v.Value)
	}
}

// PrintHelp prints help information including application version, environment
// variable configuration, and details about .env file handling to the provided
// writer
//
// # Parameters
//
//   - cfg: Configuration object containing app name and config directory path
//
//   - printer: Output destination for the help text
//
// # Expected Behaviour
//
// Prints application name and version followed by environment variable
// configuration details, explains .env file behaviour including automatic
// loading and custom path options, and displays current configuration values
// using PrintEnv. Outputs all information to the specified writer
func PrintHelp(cfg *C, printer io.Writer) {
	_, _ = fmt.Fprintf(
		printer,
		"Environment variables that configure:\n\n",
	)
	env.Usage(cfg, printer, &env.Options{SliceSep: ","})
	_, _ = fmt.Fprintf(
		printer,
		`CLI parameter 'help' also prints this information\n
use the parameter 'env' to print out the current configuration to the terminal

current configuration:

`,
	)
	PrintEnv(cfg, printer)
	return
}

// HelpRequested determines if the command line arguments indicate a request for help
//
// # Return Values
//
//   - help: A boolean value indicating true if a help flag was detected in the
//     command line arguments, false otherwise
//
// # Expected Behaviour
//
// The function checks the first command line argument for common help flags and
// returns true if any of them are present. Returns false if no help flag is found
func HelpRequested() (help bool) {
	if len(os.Args) > 1 {
		switch strings.ToLower(os.Args[1]) {
		case "help", "-h", "--h", "-help", "--help", "?":
			help = true
		}
	}
	return
}

var cfg *C

func run(ctx context.Context) error {
	var err error
	cfg = &C{}
	if err = env.Load(cfg, &env.Options{SliceSep: ","}); chk.T(err) {
		return err
	}
	if cfg.Conf == "" || strings.Contains(cfg.Conf, "~") {
		cfg.Conf = strings.Replace(cfg.Conf, "~", os.Getenv("HOME"), 1)
	}
	if cfg.Cache == "" || strings.Contains(cfg.Cache, "~") {
		cfg.Cache = strings.Replace(cfg.Cache, "~", os.Getenv("HOME"), 1)
	}
	if GetEnv() {
		PrintEnv(cfg, os.Stdout)
		os.Exit(0)
	}
	if HelpRequested() {
		PrintHelp(cfg, os.Stderr)
		os.Exit(0)
	}
	if cfg.Cache == "" {
		return fmt.Errorf("no cache specified")
	}
	srv, httpHandler, err := setupServer(
		cfg.Addr, cfg.Conf, cfg.Cache, cfg.Email, cfg.HSTS, cfg,
	)
	if err != nil {
		return err
	}
	srv.ReadHeaderTimeout = 5 * time.Second
	if cfg.RTo > 0 {
		srv.ReadTimeout = cfg.RTo
	}
	if cfg.WTo > 0 {
		srv.WriteTimeout = cfg.WTo
	}
	group, ctx := errgroup.WithContext(ctx)
	if cfg.HTTP != "" {
		httpServer := http.Server{
			Addr:         cfg.HTTP,
			Handler:      httpHandler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		group.Go(func() error { return httpServer.ListenAndServe() })
		group.Go(
			func() error {
				<-ctx.Done()
				ctx, cancel := context.WithTimeout(
					context.Background(), time.Second,
				)
				defer cancel()
				return httpServer.Shutdown(ctx)
			},
		)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || cfg.Idle == 0 {
		group.Go(func() error { return srv.ListenAndServeTLS("", "") })
	} else {
		group.Go(
			func() error {
				ln, err := net.Listen("tcp", srv.Addr)
				if err != nil {
					return err
				}
				defer ln.Close()
				ln = tcpKeepAliveListener{
					d:           cfg.Idle,
					TCPListener: ln.(*net.TCPListener),
				}
				return srv.ServeTLS(ln, "", "")
			},
		)
	}
	group.Go(
		func() error {
			<-ctx.Done()
			ctx, cancel := context.WithTimeout(
				context.Background(), time.Second,
			)
			defer cancel()
			return srv.Shutdown(ctx)
		},
	)
	return group.Wait()
}

// TLSConfig returns a TLSConfig that works with a LetsEncrypt automatic SSL cert issuer as well
// as any provided .pem certificates from providers.
//
// The certs are provided in the form "example.com:/path/to/cert.pem"
func TLSConfig(m *autocert.Manager, certs ...string) (tc *tls.Config) {
	certMap := make(map[string]*tls.Certificate)
	var mx sync.Mutex
	for _, cert := range certs {
		split := strings.Split(cert, ":")
		if len(split) != 2 {
			log.E.F("invalid certificate parameter format: `%s`", cert)
			continue
		}
		var err error
		var c tls.Certificate
		if c, err = tls.LoadX509KeyPair(
			split[1]+".crt", split[1]+".key",
		); chk.E(err) {
			continue
		}
		certMap[split[0]] = &c
	}
	tc = m.TLSConfig()
	tc.GetCertificate = func(helo *tls.ClientHelloInfo) (
		cert *tls.Certificate, err error,
	) {
		mx.Lock()
		var own string
		for i := range certMap {
			// to also handle explicit subdomain certs, prioritize over a root wildcard.
			if helo.ServerName == i {
				own = i
				break
			}
			// if it got to us and ends in the same name dot tld assume the subdomain was
			// redirected or it's a wildcard certificate, thus only the ending needs to match.
			if strings.HasSuffix(helo.ServerName, i) {
				own = i
				break
			}
		}
		if own != "" {
			defer mx.Unlock()
			return certMap[own], nil
		}
		mx.Unlock()
		return m.GetCertificate(helo)
	}
	return
}

func setupServer(
	addr, mapfile, cacheDir, email string, hsts bool, a *C,
) (*http.Server, http.Handler, error) {
	mapping, err := readMapping(mapfile)
	if err != nil {
		return nil, nil, err
	}
	proxy, err := setProxy(mapping)
	if err != nil {
		return nil, nil, err
	}
	if hsts {
		proxy = &hstsProxy{proxy}
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, nil, fmt.Errorf(
			"cannot create cache directory %q: %v", cacheDir, err,
		)
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(keys(mapping)...),
		Email:      email,
	}
	srv := &http.Server{
		Handler:   proxy,
		Addr:      addr,
		TLSConfig: TLSConfig(&m, a.Certs...),
	}
	return srv, m.HTTPHandler(nil), nil
}

func setProxy(mapping map[string]string) (http.Handler, error) {
	if len(mapping) == 0 {
		return nil, fmt.Errorf("empty mapping")
	}
	mux := http.NewServeMux()
	for hostname, backendAddr := range mapping {
		hn, ba := hostname, backendAddr // intentional shadowing
		if strings.ContainsRune(hn, os.PathSeparator) {
			return nil, fmt.Errorf("invalid hostname: %q", hn)
		}
		network := "tcp"
		if ba != "" && ba[0] == '@' && runtime.GOOS == "linux" {
			// append \0 to address so addrlen for connect(2) is
			// calculated in a way compatible with some other
			// implementations (i.e. uwsgi)
			network, ba = "unix", ba+string(byte(0))
		} else if strings.HasPrefix(ba, "git+") {
			GoVanity(hn, ba, mux)
			continue
		} else if filepath.IsAbs(ba) {
			network = "unix"
			switch {
			case strings.HasSuffix(ba, string(os.PathSeparator)):
				// path specified as directory with explicit trailing slash; add
				// this path as static site
				fs := http.FileServer(http.Dir(ba))
				mux.Handle(hn+"/", fs)
				continue
			case strings.HasSuffix(ba, "nostr.json"):
				if err := NostrDNS(hn, ba, mux); err != nil {
					continue
				}
				continue
			}
		} else if u, err := url.Parse(ba); err == nil {
			switch u.Scheme {
			case "http", "https":
				rp := newSingleHostReverseProxy(u)
				rp.ErrorLog = log2.New(io.Discard, "", 0)
				rp.BufferPool = bufPool{}
				mux.Handle(hn+"/", rp)
				continue
			}
		}
		rp := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = req.Host
				req.Header.Set("X-Forwarded-Proto", "https")
			},
			Transport: &http.Transport{
				Dial: func(netw, addr string) (net.Conn, error) {
					return net.DialTimeout(network, ba, 5*time.Second)
				},
			},
			ErrorLog:   log2.New(io.Discard, "", 0),
			BufferPool: bufPool{},
		}
		mux.Handle(hn+"/", rp)
	}
	return mux, nil
}

func readMapping(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if b := sc.Bytes(); len(b) == 0 || b[0] == '#' {
			continue
		}
		s := strings.SplitN(sc.Text(), ":", 2)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid line: %q", sc.Text())
		}
		m[strings.TrimSpace(s[0])] = strings.TrimSpace(s[1])
	}
	return m, sc.Err()
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type hstsProxy struct {
	http.Handler
}

func (p *hstsProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(
		"Strict-Transport-Security",
		"max-age=31536000; includeSubDomains; preload",
	)
	p.Handler.ServeHTTP(w, r)
}

type bufPool struct{}

func (bp bufPool) Get() []byte  { return *(bufferPool.Get().(*[]byte)) }
func (bp bufPool) Put(b []byte) { bufferPool.Put(&b) }

var bufferPool = &sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// newSingleHostReverseProxy is a copy of httputil.NewSingleHostReverseProxy
// with addition of "X-Forwarded-Proto" header.
func newSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	return &httputil.ReverseProxy{Director: director}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	d time.Duration
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	if ln.d == 0 {
		return tc, nil
	}
	return timeoutConn{d: ln.d, TCPConn: tc}, nil
}

// timeoutConn extends deadline after successful read or write operations
type timeoutConn struct {
	d time.Duration
	*net.TCPConn
}

func (c timeoutConn) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

func (c timeoutConn) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

// GoVanity configures an HTTP handler for redirecting requests to vanity URLs
// based on the provided hostname and backend address.
//
// # Parameters
//
// - hn (string): The hostname associated with the vanity URL.
//
// - ba (string): The backend address, expected to be in the format
// "git+<repository-path>".
//
// - mux (*http.ServeMux): The HTTP serve multiplexer where the handler will be
// registered.
//
// # Expected behaviour
//
// - Splits the backend address to extract the repository path from the "git+" prefix.
//
// - If the split fails, logs an error and returns without registering a handler.
//
// - Generates an HTML redirect page containing metadata for Go import and
// redirects to the extracted repository path.
//
// - Registers a handler on the provided ServeMux that serves this redirect page
// when requests are made to the specified hostname.
func GoVanity(hn, ba string, mux *http.ServeMux) {
	split := strings.Split(ba, "git+")
	if len(split) != 2 {
		log.E.Ln("invalid go vanity redirect: %s: %s", hn, ba)
		return
	}
	redirector := fmt.Sprintf(
		`<html><head><meta name="go-import" content="%s git %s"/><meta http-equiv = "refresh" content = " 3 ; url = %s"/></head><body>redirecting to <a href="%s">%s</a></body></html>`,
		hn, split[1], split[1], split[1], split[1],
	)
	mux.HandleFunc(
		hn+"/",
		func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set(
				"Access-Control-Allow-Methods",
				"GET,HEAD,PUT,PATCH,POST,DELETE",
			)
			writer.Header().Set("Access-Control-Allow-Origin", "*")
			writer.Header().Set("Content-Type", "text/html")
			writer.Header().Set(
				"Content-Length", fmt.Sprint(len(redirector)),
			)
			writer.Header().Set(
				"strict-transport-security",
				"max-age=0; includeSubDomains",
			)
			fmt.Fprint(writer, redirector)
		},
	)
}

type NostrJSON struct {
	Names  map[string]string   `json:"names"`
	Relays map[string][]string `json:"relays"`
}

// NostrDNS handles the configuration and registration of a Nostr DNS endpoint
// for a given hostname and backend address.
//
// # Parameters
//
// - hn (string): The hostname for which the Nostr DNS entry is being configured.
//
// - ba (string): The path to the JSON file containing the Nostr DNS data.
//
// - mux (*http.ServeMux): The HTTP serve multiplexer to which the Nostr DNS
// handler will be registered.
//
// # Return Values
//
// - err (error): An error if any step fails during the configuration or
// registration process.
//
// # Expected behaviour
//
// - Reads the JSON file specified by `ba` and parses its contents into a
// NostrJSON struct.
//
// - Registers a new HTTP handler on the provided `mux` for the
// `.well-known/nostr.json` endpoint under the specified hostname.
//
// - The handler serves the parsed Nostr DNS data with appropriate HTTP headers
// set for CORS and content type.
func NostrDNS(hn, ba string, mux *http.ServeMux) (err error) {
	log.T.Ln(hn, ba)
	var fb []byte
	if fb, err = os.ReadFile(ba); chk.E(err) {
		return
	}
	var v NostrJSON
	if err = json.Unmarshal(fb, &v); chk.E(err) {
		return
	}
	var jb []byte
	if jb, err = json.Marshal(v); chk.E(err) {
		return
	}
	nostrJSON := string(jb)
	mux.HandleFunc(
		hn+"/.well-known/nostr.json",
		func(writer http.ResponseWriter, request *http.Request) {
			log.T.Ln("serving nostr json to", hn)
			writer.Header().Set(
				"Access-Control-Allow-Methods",
				"GET,HEAD,PUT,PATCH,POST,DELETE",
			)
			writer.Header().Set("Access-Control-Allow-Origin", "*")
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set(
				"Content-Length", fmt.Sprint(len(nostrJSON)),
			)
			writer.Header().Set(
				"strict-transport-security",
				"max-age=0; includeSubDomains",
			)
			fmt.Fprint(writer, nostrJSON)
		},
	)
	return
}
