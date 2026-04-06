# BoxGuard — Vagrant Box Vulnerability Scanner

BoxGuard scans Vagrant boxes and systems reachable over SSH to help surface security issues.

## Features

- **OS detection**: Automatic OS identification (Ubuntu, Debian, RHEL, CentOS, Rocky Linux, AlmaLinux)
- **Package inventory**: Enumerates installed packages on the target
- **Real CVE integration**: CVE data via OSV.dev and Ubuntu USN feeds
- **Hybrid matching**: Combines real CVE data with stub rules for broader coverage
- **Multiple output formats**: Table and JSON reporting

## Requirements

Go 1.22 or later (see [`go.mod`](go.mod)).

## Install

```bash
go mod tidy
go build -o boxguard .
```

## Usage

### Scan a Vagrant box

```bash
# Using the Vagrantfile in the current directory (with test packages)
./boxguard scan --vagrant-path .

# Target a specific machine
./boxguard scan --vagrant-path . --vagrant-machine web-server
```

### CVE testing

```bash
./test-cves.sh

# Recreate the Vagrant box (for CVE test packages)
vagrant destroy -f && vagrant up
```

### Scan a remote host over SSH

```bash
./boxguard scan --ssh-host 192.168.1.100 --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa
```

### Output formats

```bash
# Table (default)
./boxguard scan --vagrant-path .

# JSON
./boxguard scan --vagrant-path . --output json
```

## Sample output

```
OS: Ubuntu 18.04 LTS (ID=ubuntu, VERSION_ID=18.04)

+------+---------+-----------------+----------------------+-------------------+-----+--------+------+
| SEV  | PKG     | VERSION         | VULN                 | TITLE             | FIX | SOURCE | CVSS |
+------+---------+-----------------+----------------------+-------------------+-----+--------+------+
| HIGH | openssl | 1.1.0g-2ubuntu4 | CVE-2021-3711        | OpenSSL: SM2 decryption | 1.1.1l | osv    | 7.5  |
| HIGH | sudo    | 1.8.21p2-3      | CVE-2021-3156        | sudo: heap-based buffer overflow | 1.9.5p1 | osv    | 7.0  |
+------+---------+-----------------+----------------------+-------------------+-----+--------+------+

Packages: 171, Findings: 2
Stub findings: 0
OSV findings: 2
```

## Data sources

### OSV.dev

- Open source vulnerability database
- CVE, GHSA, and other advisories
- CVSS scores and detailed metadata

### Ubuntu USN (Ubuntu Security Notices)

- Ubuntu-specific security notices
- CVE information tailored to Ubuntu packages

### Stub database

- Simple rule-based fallback when live CVE data is unavailable

## Architecture

```
cmd/
├── root.go          # Root command and global flags
└── scan.go          # Scan command

pkg/
├── inventory/       # Package inventory
├── model/           # Data models
├── report/          # Reporting (table, JSON)
├── sources/         # SSH, Vagrant integration
└── vuln/            # Vulnerability matching
    ├── hybrid.go    # Hybrid matcher
    ├── osv.go       # OSV.dev integration
    ├── stubdb.go    # Stub rules
    └── ubuntu_usn.go # Ubuntu USN feed
```

## Development

### Adding a vulnerability source

1. Add a new file under `pkg/vuln/`
2. Implement the `Advisory` workflow used by the matcher
3. Wire it into `HybridMatcher`

### Adding a new OS

1. Extend OS detection under `pkg/inventory/`
2. Implement package listing for that OS
3. Update ecosystem mapping for OSV/USN as needed

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see [`LICENSE`](LICENSE).
