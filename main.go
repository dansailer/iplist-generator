package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	logger "github.com/sirupsen/logrus"
)

type Source struct {
	URL      string `yaml:"url"`
	Name     string `yaml:"name"`
	Category string `yaml:"category"`
}

type Config struct {
	Sources []Source `yaml:"sources"`
}

var (
	sourceListPath string
	logLevel       string
	searchDomain   string
	dnsServers     []string
	enableIPv4     bool
	enableIPv6     bool
	client         *MerkleMapClient
)

func init() {
	flag.StringVar(&sourceListPath, "config", "sourcelist.yml", "Path to source list configuration file")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	dnsServersFlag := flag.String("dns-servers", "1.1.1.1:53,9.9.9.9:53,8.8.8.8:53,130.59.31.251:53,208.67.220.220:53", "Comma-separated list of DNS servers to use for lookups, e.g. 1.1.1.1:53,8.8.8.8:53,9.9.9.9:53,,130.59.31.251:53 or 208.67.220.220:53")
	flag.BoolVar(&enableIPv4, "ipv4", true, "Enable IPv4 lookups (default: true)")
	flag.BoolVar(&enableIPv6, "ipv6", false, "Enable IPv6 lookups (default: false)")
	flag.StringVar(&searchDomain, "search-domain", "", "Just return IPs for this domain.")
	flag.Parse()
	dnsServers = strings.Split(*dnsServersFlag, ",")

	logger.SetFormatter(&logger.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	logger.SetOutput(os.Stdout)
}

func main() {
	flag.Parse()
	level, err := logger.ParseLevel(logLevel)
	if err != nil {
		logger.WithError(err).Fatal("Invalid log level")
		return
	}
	logger.SetLevel(level)

	if searchDomain != "" {
		logger.Infof("Looking up DNS records for %s", searchDomain)
		ipv4s, ipv6s := lookupIPs(searchDomain)
		// Log IPv4 results
		for _, ipv4 := range ipv4s {
			logger.Infof("IPv4 record for %s: %s", searchDomain, ipv4)
		}
		// Log IPv6 results
		for _, ipv6 := range ipv6s {
			logger.Infof("IPv6 record for %s: %s", searchDomain, ipv6)
		}
		return
	}

	client = NewMerkleMapClient("https://api.merklemap.com", 30*time.Second, logger.StandardLogger())

	logger.Info("Starting domain list processing")
	config, err := loadConfig(sourceListPath)
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
		return
	}
	for _, source := range config.Sources {
		logger.Infof("Processing source: %s", source.Name)
		timestamp := time.Now().Format("2006-01-02_150405")
		filename := fmt.Sprintf("%s_%s", source.Name, timestamp)

		defer func(f string) {
			os.Remove(f)
		}(filename)

		if err := downloadFile(filename, source.URL); err != nil {
			logger.WithError(err).Errorf("Failed to download %s for %s", source.Category, source.Name)
			continue
		}

		logger.Infof("Extracting downloaded %s for %s", source.Category, source.Name)
		inputFile, err := os.Open(filename)
		if err != nil {
			logger.WithError(err).Errorf("Error opening domain list %s", filename)
			return
		}
		defer inputFile.Close()

		var domains []string
		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if source.Category == "dnsfilterlist" {
				if strings.HasPrefix(line, "full:") {
					line = strings.TrimPrefix(line, "full:")
					if idx := strings.Index(line, " "); idx != -1 {
						line = line[:idx]
					}
				} else if strings.HasPrefix(line, "include:") {
					logger.Infof("Interesting domain list to %s", line)
					continue
				} else {
					// Take everything before the first space
					if idx := strings.Index(line, " "); idx != -1 {
						line = line[:idx]
					}
					subdomains, err := client.FetchSubDomains(context.Background(), line)
					if err != nil {
						logger.Fatalf("Failed to fetch subdomains: %v", err)
					}
					domains = append(domains, subdomains...)

				}
			}

			logger.Debugf("Processing line: %s", line)
			if !isValidDomain(line) {
				logger.Warnf("Invalid domain found: %s", line)
				continue
			}
			domains = append(domains, line)
		}
		if err := scanner.Err(); err != nil {
			logger.WithError(err).Errorf("Error reading domain list %s", filename)
			return
		}

		writeToFile(fmt.Sprintf("%s_domain_list.txt", source.Name), domains)

		logger.Info("Performing DNS lookups")
		var ipv4Results, ipv6Results []string

		for _, domain := range domains {
			logger.Debugf("Looking up DNS records for %s", domain)
			ipv4s, ipv6s := lookupIPs(domain)
			ipv4Results = append(ipv4Results, ipv4s...)
			ipv6Results = append(ipv6Results, ipv6s...)
		}
		if enableIPv4 {
			writeToFile(fmt.Sprintf("%s_ipv4_list.txt", source.Name), ipv4Results)
		}
		if enableIPv6 {
			writeToFile(fmt.Sprintf("%s_ipv6_list.txt", source.Name), ipv6Results)
		}
	}
	logger.Info("Processing complete!")
}

func lookupIPs(domain string) ([]string, []string) {
	var ipv4s, ipv6s []string
	client := &dns.Client{}

	for _, server := range dnsServers {
		// Lookup A records
		if enableIPv4 {
			m := &dns.Msg{}
			m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
			r, _, err := client.Exchange(m, server)
			if err == nil {
				for _, answer := range r.Answer {
					if aRecord, ok := answer.(*dns.A); ok {
						ipv4s = append(ipv4s, aRecord.A.String())
					}
				}
			}
		}

		// Lookup AAAA records
		if enableIPv6 {
			m := &dns.Msg{}
			m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
			r, _, err := client.Exchange(m, server)
			if err == nil {
				for _, answer := range r.Answer {
					if aaaaRecord, ok := answer.(*dns.AAAA); ok {
						ipv6s = append(ipv6s, aaaaRecord.AAAA.String())
					}
				}
			}
		}
	}

	logger.Debugf("DNS lookup complete for %s", domain)
	return ipv4s, ipv6s
}
