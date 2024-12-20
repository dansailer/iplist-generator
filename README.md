# iplist-generator

A Go application that processes lists of domains from various sources, performs DNS lookups, and generates separate IPv4 and IPv6 address lists, as well as formatted domain lists for DNS filtering.

## Features

- Configurable domain list sources via YAML configuration
- Support for both IPv4 (A records) and IPv6 (AAAA records) lookups
- Customizable DNS server selection
- Automatic deduplication and sorting of IP addresses
- Configurable logging levels
- Generates multiple output formats:
  - IPv4 address lists
  - IPv6 address lists
  - DNS filter lists (domain-based blocking)
- Handling of simple domain lists
- Handling of DNS filter lists as created by [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community):
  - "full:" prefix for exact domain matches
  - Default wildcard matching for catching all subdomains
  - Automatic subdomain discovery using [MerkleMap](https://www.merklemap.com)

> [!TIP]
> For YouTube use the excellent work of [touhidurrr/iplist-youtube](https://github.com/touhidurrr/iplist-youtube/blob/main/ipv4_list.txt)

## Prerequisites

- Go 1.x or higher
- External dependencies:
  - github.com/miekg/dns
  - github.com/sirupsen/logrus
  - gopkg.in/yaml.v3

## Usage in Terraform and Ubiquity provider

```hcl
data "http" "twitch_cidrv4_list" {
  url = "https://raw.githubusercontent.com/dansailer/iplist-generator/refs/heads/main/twitch_ipv4_list.txt"
}

resource "unifi_firewall_group" "twitchv4" {
  name = "Twitch IPv4"
  type = "address-group"

  members = split("\n", trimspace(data.http.twitch_cidrv4_list.response_body))
}
```

## Influences

- https://github.com/touhidurrr/iplist-youtube
- https://github.com/nickspaargaren/no-google
- https://github.com/v2fly/domain-list-community
- https://www.merklemap.com - Used for subdomain discovery
