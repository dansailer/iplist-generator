package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// MerkleMapClient provides an interface to interact with the MerkleMap API
// for retrieving domain information.
type MerkleMapClient struct {
	baseURL        string
	httpClient     *http.Client
	logger         *logrus.Logger
	defaultTimeout time.Duration
}

// ApiResponse represents the structure of the API response from MerkleMap.
type ApiResponse struct {
	Count   int      `json:"count"`
	Results []Domain `json:"results"`
}

// Domain represents a single domain entry in the API response.
type Domain struct {
	Domain string `json:"domain"`
}

// NewMerkleMapClient creates a new MerkleMapClient with the specified base URL and timeout.
// It configures an HTTP client with optimized connection settings.
//
// Parameters:
//   - baseURL: The base URL for the MerkleMap API endpoint
//   - timeout: The maximum duration to wait for HTTP requests to complete
//   - logger: The logger to use for logging HTTP requests and responses
//
// Returns:
//   - *MerkleMapClient: A configured client instance ready for making API requests
func NewMerkleMapClient(baseURL string, timeout time.Duration, logger *logrus.Logger) *MerkleMapClient {
	if logger == nil {
		logger = logrus.New()
	}
	return &MerkleMapClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:       100,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: true,
				MaxConnsPerHost:    100,
				DisableKeepAlives:  false,
			},
		},
		logger: logger,
	}
}

// FetchSubDomains retrieves all subdomains matching the given query string.
// It automatically handles pagination and returns a consolidated list of domains.
//
// Parameters:
//   - ctx: The context to use for cancellation and timeouts
//   - query: The search query string to match against domains
//
// Returns:
//   - []string: List of matching domain names
//   - error: Non-nil if the query is empty or any API request fails
func (c *MerkleMapClient) FetchSubDomains(ctx context.Context, query string) ([]string, error) {
	if query == "" {
		return nil, fmt.Errorf("empty query parameter")
	}

	var allDomains []string
	page := 0

	for {
		domains, err := c.fetchPage(ctx, query, page)
		if err != nil {
			return allDomains, fmt.Errorf("failed to fetch page %d: %w", page, err)
		}

		if len(domains) == 0 {
			break
		}

		allDomains = append(allDomains, domains...)
		page++
	}

	return allDomains, nil
}

// fetchPage retrieves a single page of domain results from the API.
// It handles the HTTP request, response parsing, and basic error handling.
//
// Parameters:
//   - ctx: The context to use for cancellation and timeouts
//   - query: The search query string to match against domains
//   - page: The page number to retrieve (zero-based)
//
// Returns:
//   - []string: List of domain names from the requested page
//   - error: Non-nil if the request fails, response is invalid, or parsing fails
func (c *MerkleMapClient) fetchPage(ctx context.Context, query string, page int) ([]string, error) {
	apiURL, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	apiURL.Path = strings.TrimSuffix(apiURL.Path, "/") + "/search"

	q := apiURL.Query()
	q.Set("query", "*."+query)
	q.Set("page", strconv.Itoa(page))
	apiURL.RawQuery = q.Encode()

	apiURL.RawQuery = strings.Replace(apiURL.RawQuery, "%2A", "*", 1)

	c.logger.Debugf("curl '%s'\n", apiURL.String())

	maxRetries := 3
	backoff := 100 * time.Millisecond
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			c.logger.Debugf("Retry attempt %d for query '%s' page %d", attempt, query, page)
			// Wait before retrying, with exponential backoff
			select {
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to execute request: %w", err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusTooManyRequests {
				// Get retry-after header, default to 1 second if not present
				retryAfter := 1 * time.Second
				if retryHeader := resp.Header.Get("Retry-After"); retryHeader != "" {
					if seconds, err := strconv.Atoi(retryHeader); err == nil {
						retryAfter = time.Duration(seconds) * time.Second
					}
				}
				c.logger.Debugf("Rate limited, waiting %v before retry", retryAfter)
				select {
				case <-time.After(retryAfter):
					continue
				}
			}
			lastErr = fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
			continue
		}

		var apiResponse ApiResponse
		if err := json.Unmarshal(body, &apiResponse); err != nil {
			lastErr = fmt.Errorf("failed to decode API response: %w", err)
			continue
		}

		return filterDomains(apiResponse.Results), nil
	}

	return nil, fmt.Errorf("failed after %d retry attempts with error: %w", maxRetries, lastErr)
}

// filterDomains processes the API results and returns a filtered list of valid domains.
//
// Parameters:
//   - results: Slice of Domain objects from the API response
//
// Returns:
//   - []string: Filtered list of valid domain names
func filterDomains(results []Domain) []string {
	filtered := make([]string, 0, len(results))
	for _, result := range results {
		if isValidResultDomain(result.Domain) {
			filtered = append(filtered, result.Domain)
		}
	}
	return filtered
}

// isValidResultDomain checks if a domain string meets the required validation criteria.
//
// Parameters:
//   - domain: The domain string to validate
//
// Returns:
//   - bool: true if the domain meets all validation criteria, false otherwise
func isValidResultDomain(domain string) bool {
	return domain != "" &&
		!strings.HasPrefix(domain, "*.") &&
		!strings.Contains(domain, "..") && // prevent path traversal
		len(domain) <= 253 // max domain length per RFC
}
