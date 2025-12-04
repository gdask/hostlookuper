// main hostlookuper
package main

import (
	"context"
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/miekg/dns"
	"github.com/peterbourgon/ff/v3"
	"github.com/postfinance/flash"
	"go.uber.org/zap"
)

const (
	dnsDurationName    = "hostlookuper_dns_lookup_duration_seconds"
	dnsLookupTotalName = "hostlookuper_dns_lookup_total"
	dnsErrorsTotalName = "hostlookuper_dns_errors_total"
)

//nolint:gochecknoglobals // There is no other way than doing so. Values will be set on build.
var (
	version, date string
	commit        = "12345678"
)

// DNSServer describes a protocol (network) and an address to contact a dns server
type DNSServer struct {
	network string
	address string
	name    string
}

type Histogram interface {
	Update(v float64)
	UpdateDuration(start time.Time)
}

var histogramGetter func(string) Histogram

func (srv DNSServer) String() string {
	return fmt.Sprintf("%s://%s", srv.network, srv.name)
}

func parseDNSServers(l *zap.SugaredLogger, dnsServersStr string) []DNSServer {
	dnsServersList := strings.Split(dnsServersStr, ",")
	dnsServers := make([]DNSServer, 0, len(dnsServersList))

	for _, dnsServer := range dnsServersList {
		var network, address, name string

		spl := strings.Split(dnsServer, "://")

		switch len(spl) {
		case 1:
			network = "udp"
			address = spl[0]

		case 2:
			network = spl[0]
			address = spl[1]

		default:
			l.Fatalw("parsing dns servers list failed, wrong format used",
				"val", dnsServer)
		}

		if !strings.Contains(address, ":") { // port was not specified, implying port 53
			address += ":53"
		}

		name = address
		spl = strings.Split(address, ":")
		host, port := spl[0], spl[1]

		if ip := net.ParseIP(host); ip == nil { // dns server specified using DNS name
			ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
			if err != nil {
				l.Fatalw("could not resolve dns server ip address", "host", host, err)
			}

			if len(ips) > 1 {
				l.Warnw("multiple DNS server IP resolved from host. arbitrarily picking the first resolved ip", "host", host, "resolved_ips", ips)
			}

			address = fmt.Sprintf("%v:%s", ips[0], port)
		}

		l.Infow("added a new DNS server", "name", name, "network", network, "address", address)

		dnsServers = append(dnsServers, DNSServer{
			network: network,
			address: address,
			name:    name,
		})
	}

	return dnsServers
}

// parseHosts returns a hosts slice read either from a file (if hostsFile is
// non-empty) or from the comma-separated hostsVal. It trims whitespace,
// ignores blank lines and lines starting with '#'. On file errors or when
// the file contains no hosts, an error is returned.
func parseHosts(l *zap.SugaredLogger, hostsVal, domainProbes string) (hosts, error) {
	if domainProbes != "" {
		f, err := os.Open(domainProbes)
		if err != nil {
			return nil, fmt.Errorf("could not open domain probes file %s: %w", domainProbes, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		var hs []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hs = append(hs, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading domain probes file %s: %w", domainProbes, err)
		}
		if len(hs) == 0 {
			return nil, fmt.Errorf("domain probes file contains no hosts: %s", domainProbes)
		}

		return hosts(hs), nil
	}

	// fall back to comma-separated flag value
	return hosts(strings.Split(hostsVal, ",")), nil
}

func main() {
	fs := flag.NewFlagSet("hostlookuper", flag.ExitOnError)

	var (
		debug               = fs.Bool("debug", false, "enable verbose logging")
		prometheusHistogram = fs.Bool("prom-histogram", false, "use Prometheus-compatible (le) histograms (default is false)")
		interval            = fs.Duration("interval", 5*time.Second, "interval between DNS checks. must be in Go time.ParseDuration format, e.g. 5s or 5m or 1h, etc")
		timeout             = fs.Duration("timeout", 5*time.Second, "maximum timeout for a DNS query. must be in Go time.ParseDuration format, e.g. 5s or 5m or 1h, etc")
		listen              = fs.String("listen", ":9090", "address on which hostlookuper listens. e.g. 0.0.0.0:9090")
		hostsVal            = fs.String("hosts", "google.ch,ch.ch", "comma-separated list of hosts against which to perform DNS lookups")
		domainProbes        = fs.String("domain-probes", "", "path to a file containing a list of domains to probe (one per line). if set, this overrides the 'hosts' flag")
		dnsServersVal       = fs.String("dns-servers", "udp://9.9.9.9:53,udp://8.8.8.8:53,udp://one.one.one.one:53", "comma-separated list of DNS servers. if the protocol is omitted, udp is implied, and if the port is omitted, 53 is implied")
	)

	err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("HOSTLOOKUPER"))
	if err != nil {
		fmt.Printf("unable to parse args/envs, exiting. error message: %v", err)

		os.Exit(2)
	}

	logger := flash.New(flash.WithoutCaller())
	logger.SetDebug(*debug)
	l := logger.Get()

	// Parse hosts from flag or file (delegated to helper)
	hosts, err := parseHosts(l, *hostsVal, *domainProbes)
	if err != nil {
		l.Fatalw("could not parse hosts",
			"err", err,
		)
	}

	if err := hosts.isValid(); err != nil {
		l.Warnw("parsing hosts failed in global dns",
			"hosts", hosts,
			"domain_probes_file", *domainProbes,
			"hosts_flag", *hostsVal,
			"err", err,
		)
	}

	histogramGetter = func(name string) Histogram {
		if *prometheusHistogram {
			return metrics.GetOrCreatePrometheusHistogram(name)
		} else {
			return metrics.GetOrCreateHistogram(name)
		}
	}

	dnsServers := parseDNSServers(l, *dnsServersVal)

	for _, host := range hosts {
		for _, dnsServer := range dnsServers {
			look := newLookuper(host, dnsServer, timeout, l)

			go func() {
				look.start(*interval)
			}()
		}
	}

	http.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		metrics.WritePrometheus(w, false)
	})

	l.Infow("starting server",
		"listen", listen,
		"interval", interval,
		"hosts", hostsVal,
		"version", version,
		"commit", commit,
		"date", date,
	)

	srv := &http.Server{
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           http.DefaultServeMux,
		Addr:              *listen,
	}
	l.Fatal(srv.ListenAndServe())
}

type lookuper struct {
	host      string
	l         *zap.SugaredLogger
	c         *dns.Client
	dnsServer DNSServer
	labels    string
}

func newLookuper(host string, dnsServer DNSServer, timeout *time.Duration, log *zap.SugaredLogger) *lookuper {
	c := dns.Client{
		Net:     dnsServer.network,
		Timeout: *timeout,
	}

	return &lookuper{
		host:      host,
		labels:    fmt.Sprintf("host=%q,dns_server=%q", host, dnsServer),
		l:         log.With("host", host, "dnsServer", dnsServer),
		c:         &c,
		dnsServer: dnsServer,
	}
}

func (l *lookuper) start(interval time.Duration) {
	//nolint:gosec // No need for a cryptographic secure random number since this is only used for a jitter.
	jitter := time.Duration(rand.Float64() * float64(500*time.Millisecond))

	l.l.Infow("start delayed",
		"jitter", jitter,
	)

	metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", dnsErrorsTotalName, l.labels)).Set(0)
	time.Sleep(jitter)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		l.l.Debug("lookup host")

		m := new(dns.Msg)
		m.SetQuestion(fmt.Sprintf("%s.", l.host), dns.TypeA)
		msg, rtt, err := l.c.Exchange(m, l.dnsServer.address)
		if err != nil {
			metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", dnsLookupTotalName, l.labels)).Inc()
			metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", dnsErrorsTotalName, l.labels)).Inc()

			l.l.Errorw("dns lookup failed",
				"host", l.host,
				"time", rtt,
				"err", err,
			)

			continue
		}

		rcodeStr, ok := dns.RcodeToString[msg.Rcode]

		if !ok { // if rcode not known in table.
			rcodeStr = fmt.Sprintf("%#x", msg.Rcode)
		}

		metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s,rcode=%q}",
			dnsLookupTotalName, l.labels, rcodeStr)).Inc()
		histogramGetter(fmt.Sprintf("%s{%s}",
			dnsDurationName, l.labels)).Update(rtt.Seconds())

		l.l.Debugw("lookup result",
			"time", rtt,
			"result length", len(msg.Answer),
		)
	}
}

type hosts []string

func (h hosts) isValid() error {
	for _, host := range h {
		if _, err := net.LookupHost(host); err != nil {
			return fmt.Errorf("host %s is not valid: %s", host, err)
		}
	}

	return nil
}