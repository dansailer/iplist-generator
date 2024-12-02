package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	logger "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// sortAndUniq sorts a slice of strings and removes duplicates in-place.
// It returns a new slice containing only unique elements in sorted order.
//
// Parameters:
//   - ips: A slice of strings to be sorted and deduplicated
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

// writeToFile writes a slice of strings to a file, one string per line.
// The strings are first sorted and deduplicated.
// If an error occurs while creating the file, it will be logged and the function will return.
//
// Parameters:
//   - filename: The path to the file where the strings will be written
//   - ips: A slice of strings to be written to the file
func writeToFile(filename string, ips []string) {
	ips = sortAndUniq(ips)
	file, err := os.Create(filename)
	if err != nil {
		logger.WithError(err).Errorf("Error creating %s", filename)
		return
	}
	defer file.Close()

	for _, ip := range ips {
		file.WriteString(ip + "\n")
	}
}

// isValidDomain checks if a given string is a valid domain name.
// It returns true if the domain can be parsed as a URL and contains at least one dot.
//
// Parameters:
//   - domain: The domain name string to validate
func isValidDomain(domain string) bool {
	u, err := url.Parse("http://" + domain)
	if err != nil {
		return false
	}
	return u.Host != "" && strings.Contains(u.Host, ".")
}

// downloadFile downloads a file from the specified URL and saves it to the local filesystem.
// It returns an error if the download fails, if the HTTP status is not 200,
// or if there are any file operation errors.
//
// Parameters:
//   - filename: The path where the downloaded file will be saved
//   - url: The URL of the file to download
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

// loadConfig reads and parses a YAML configuration file into a Config struct.
// It returns a pointer to the Config struct and any error encountered during
// reading or parsing the file.
//
// Parameters:
//   - filename: The path to the YAML configuration file to load
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
