package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"flag"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Source struct {
	URL  string `yaml:"url"`
	Name string `yaml:"name"`
}

type Config struct {
	Sources []Source `yaml:"sources"`
}

var (
	sourceListPath string
	logLevel       string
	dnsServer      string
)

func init() {
	// Add flag definitions
	flag.StringVar(&sourceListPath, "config", "sourcelist.yml", "Path to source list configuration file")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&dnsServer, "dns-server", "9.9.9.9:53", "DNS server to use for lookups")

	// Configure logrus
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	log.SetOutput(os.Stdout)
}

func main() {
	// Parse flags
	flag.Parse()

	// Set log level based on flag
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.WithError(err).Fatal("Invalid log level")
		return
	}
	log.SetLevel(level)

	log.Info("Starting domain list processing")
	config, err := loadConfig(sourceListPath)
	if err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
		return
	}
	for _, source := range config.Sources {
		log.Infof("Processing source: %s", source.Name)
		timestamp := time.Now().Format("2006-01-02_150405")
		filename := fmt.Sprintf("%s_%s", source.Name, timestamp)

		defer func(f string) {
			os.Remove(f)
		}(filename)

		if err := downloadFile(filename, source.URL); err != nil {
			log.WithError(err).Errorf("Failed to download domain list for %s", source.Name)
			continue
		}

		log.Info("Extracting domains from downloaded domain list")
		inputFile, err := os.Open(filename)
		if err != nil {
			log.WithError(err).Errorf("Error opening domain list %s", filename)
			return
		}
		defer inputFile.Close()

		var domains []string
		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimPrefix(line, "full:")
			// Take everything before the first space
			if idx := strings.Index(line, " "); idx != -1 {
				line = line[:idx]
			}
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			log.Debugf("Processing line: %s", line)
			if !isValidDomain(line) {
				log.Warnf("Invalid domain found: %s", line)
				continue
			}
			domains = append(domains, line)
		}
		if err := scanner.Err(); err != nil {
			log.WithError(err).Errorf("Error reading domain list %s", filename)
			return
		}

		log.Info("Performing DNS lookups")
		var ipv4Results, ipv6Results []string

		for _, domain := range domains {
			log.Debugf("Looking up DNS records for %s", domain)
			ipv4s, ipv6s := lookupIPs(domain)
			ipv4Results = append(ipv4Results, ipv4s...)
			ipv6Results = append(ipv6Results, ipv6s...)
		}
		writeToFile(fmt.Sprintf("%s_ipv4_list.txt", source.Name), ipv4Results)
		writeToFile(fmt.Sprintf("%s_ipv6_list.txt", source.Name), ipv6Results)
	}
	log.Info("Processing complete!")
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func downloadFile(filename, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	outFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func isValidDomain(domain string) bool {
	u, err := url.Parse("http://" + domain)
	if err != nil {
		return false
	}
	return u.Host != "" && strings.Contains(u.Host, ".")
}

func lookupIPs(domain string) ([]string, []string) {
	var ipv4s, ipv6s []string
	client := &dns.Client{}

	// Lookup A records
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := client.Exchange(m, dnsServer)
	if err == nil {
		for _, answer := range r.Answer {
			if aRecord, ok := answer.(*dns.A); ok {
				ipv4s = append(ipv4s, aRecord.A.String())
			}
		}
	}

	// Lookup AAAA records
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	r, _, err = client.Exchange(m, dnsServer)
	if err == nil {
		for _, answer := range r.Answer {
			if aaaaRecord, ok := answer.(*dns.AAAA); ok {
				ipv6s = append(ipv6s, aaaaRecord.AAAA.String())
			}
		}
	}

	log.Infof("DNS lookup complete for %s", domain)
	return ipv4s, ipv6s
}

func sortAndUniq(ips []string) []string {
	sort.Strings(ips)

	// Remove duplicates in-place
	n := len(ips)
	if n == 0 {
		return ips
	}

	j := 0 // Index for the unique element
	for i := 1; i < n; i++ {
		if ips[j] != ips[i] {
			j++
			ips[j] = ips[i]
		}
	}

	return ips[:j+1]
}

func writeToFile(filename string, ips []string) {
	ips = sortAndUniq(ips)
	file, err := os.Create(filename)
	if err != nil {
		log.WithError(err).Errorf("Error creating %s", filename)
		return
	}
	defer file.Close()

	for _, ip := range ips {
		file.WriteString(ip + "\n")
	}
}
