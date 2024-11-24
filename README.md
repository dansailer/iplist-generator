# iplist-generator

A Go application that processes lists of domains from various sources, performs DNS lookups, and generates separate IPv4 and IPv6 address lists.

## Features

- Configurable domain list sources via YAML configuration
- Support for both IPv4 (A records) and IPv6 (AAAA records) lookups
- Customizable DNS server selection
- Automatic deduplication and sorting of IP addresses
- Configurable logging levels
- Handles various domain list formats including those with "full:" prefix

## Prerequisites

- Go 1.x or higher
- External dependencies:
  - github.com/miekg/dns
  - github.com/sirupsen/logrus
  - gopkg.in/yaml.v3
