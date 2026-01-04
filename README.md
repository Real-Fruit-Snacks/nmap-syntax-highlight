# Nmap Syntax Highlight for Obsidian

A powerful syntax highlighting plugin for nmap scan output, designed for **CTF players**, **penetration testers**, and **security certification students**.

Transform raw nmap output into beautifully highlighted, easily scannable security intelligence.

## Features

### Syntax Highlighting
- **Port States**: Open (green), Closed (red), Filtered (orange)
- **Critical Ports**: Extra emphasis on high-value targets (22, 80, 443, 445, 3389, etc.)
- **Services & Versions**: Purple service names, cyan version info
- **Vulnerabilities**: Glowing red CVE/MS/CWE identifiers with pulsing animation
- **Network Info**: IPv4/IPv6 addresses, hostnames, MAC addresses
- **OS Detection**: Operating system fingerprinting results
- **Script Output**: NSE script results with "interesting findings" detection

### Interactive Features
- **Filter Toolbar**: Toggle visibility of line categories (scripts, closed ports, OS info, etc.)
- **Copy Button**: One-click copy of scan output
- **Line Numbers**: Optional line numbering
- **Collapsible Summary**: Per-host breakdown with expandable details

### Smart Summary
- Automatic host/port/service extraction
- Per-host grouping for multi-target scans
- **/etc/hosts generation** with copy button
- Critical port highlighting
- Vulnerability aggregation

### Accessibility
- **Color-blind mode**: Symbols alongside colors (✓ open, ✗ closed, ― filtered)
- **Reduced motion**: Respects `prefers-reduced-motion` system setting
- **Keyboard navigation**: Full focus state support
- **Print-friendly**: Clean output for documentation

## Installation

1. Copy plugin files to your vault:
   ```
   <vault>/.obsidian/plugins/nmap-syntax-highlight/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```

2. Restart Obsidian

3. Go to **Settings → Community Plugins**

4. Enable **"Nmap Syntax Highlight"**

## Usage

Wrap your nmap output in a code block with the `nmap` language identifier:

````markdown
```nmap
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.10.100
Host is up (0.045s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.2p1 Ubuntu
80/tcp   open  http          Apache httpd 2.4.41
443/tcp  open  ssl/http      Apache httpd 2.4.41
445/tcp  open  microsoft-ds  Windows Server 2019

Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1
|     IDs:  CVE:CVE-2017-0143
```
````

You can also use `nmap-scan` as an alias.

## What Gets Highlighted

| Element | Color | Description |
|---------|-------|-------------|
| **Open ports** | Green | Port state "open" |
| **Closed ports** | Red | Port state "closed" |
| **Filtered ports** | Orange | Port state "filtered/unfiltered" |
| **Critical ports** | Bold Red + Glow | High-value targets (see list below) |
| **Services** | Purple | Service names (ssh, http, smb) |
| **Versions** | Cyan | Version information |
| **CVE/MS/CWE** | Red + Glow Animation | Vulnerability identifiers |
| **VULNERABLE** | Pulsing Red | Vulnerability indicators |
| **IP Addresses** | Blue | IPv4 and IPv6 |
| **Hostnames** | Blue | DNS names and NetBIOS names |
| **OS Detection** | Orange Background | Operating system results |
| **Script Output** | Left Border | NSE script results |
| **Warnings** | Yellow | Nmap warning messages |
| **Errors** | Red | Error messages |
| **Timing** | Cyan | Scan duration and statistics |

## Critical Ports

These ports receive extra visual emphasis when found open:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 1433 | MSSQL |
| 22 | SSH | 1521 | Oracle |
| 23 | Telnet | 2049 | NFS |
| 25 | SMTP | 3306 | MySQL |
| 53 | DNS | 3389 | RDP |
| 80 | HTTP | 5432 | PostgreSQL |
| 88 | Kerberos | 5900 | VNC |
| 110 | POP3 | 5985 | WinRM HTTP |
| 135 | MSRPC | 5986 | WinRM HTTPS |
| 139 | NetBIOS | 6379 | Redis |
| 143 | IMAP | 8080 | HTTP Proxy |
| 389 | LDAP | 9200 | Elasticsearch |
| 443 | HTTPS | 27017 | MongoDB |
| 445 | SMB | | |

**Add custom critical ports** in Settings → Advanced → Custom Critical Ports

## Settings

Access via **Settings → Community Plugins → Nmap Syntax Highlight**

### Highlighting Options
| Setting | Default | Description |
|---------|---------|-------------|
| Highlight open ports | ON | Green highlighting for open state |
| Highlight closed ports | ON | Red highlighting for closed state |
| Highlight filtered ports | ON | Orange highlighting for filtered state |
| Highlight critical ports | ON | Extra emphasis on critical ports |
| Highlight services | ON | Purple service name highlighting |
| Highlight versions | ON | Cyan version info highlighting |
| Highlight OS detection | ON | OS fingerprinting results |
| Highlight script output | ON | NSE script output styling |
| Highlight vulnerabilities | ON | CVE/vuln indicator highlighting |
| Severity highlighting | ON | Color-code CRITICAL/HIGH/MEDIUM/LOW |
| Highlight IP addresses | ON | IPv4 address highlighting |
| Highlight IPv6 addresses | ON | IPv6 address highlighting |
| Highlight hostnames | ON | Hostname highlighting |
| Highlight traceroute | ON | Traceroute hop styling |
| Highlight rDNS | ON | Reverse DNS results |
| Highlight CPE | ON | CPE identifier styling |
| Highlight port reasons | ON | Reason info from --reason flag |
| Highlight warnings | ON | Warning/error message styling |
| Highlight timing | ON | Scan duration highlighting |

### Summary Options
| Setting | Default | Description |
|---------|---------|-------------|
| Show summary | ON | Display scan summary section |
| Summary position | After | Before or after scan output |

### Display Options
| Setting | Default | Description |
|---------|---------|-------------|
| Show copy button | ON | Copy-to-clipboard button |
| Show line numbers | OFF | Line numbering |
| Show filter toolbar | ON | Category filter buttons |

### Accessibility
| Setting | Default | Description |
|---------|---------|-------------|
| Color-blind mode | OFF | Add symbols to colors |

### Advanced
| Setting | Default | Description |
|---------|---------|-------------|
| Custom critical ports | (empty) | Comma-separated port numbers |

## Filter Toolbar

When enabled, a toolbar appears above the scan output with toggle buttons:

| Filter | Hides |
|--------|-------|
| **Scripts** | NSE script output (lines starting with \|) |
| **Closed** | Closed port lines |
| **Filtered** | Filtered/unfiltered port lines |
| **OS** | OS detection lines |
| **Traceroute** | Traceroute hop lines |
| **Vulns** | Vulnerability indicators |

Click a button to hide that category. Click again to show.

## Summary Features

### Per-Host Grouping
Multi-target scans are automatically grouped by host with collapsible sections showing:
- Open/Closed/Filtered port counts
- Critical ports found
- Services detected
- OS detection results
- Vulnerabilities discovered

### /etc/hosts Generation
Automatically extracts hostname-to-IP mappings from:
- Scan report headers
- Reverse DNS records
- SMB/NetBIOS enumeration
- SSL certificate common names
- Service Info fields

One-click copy for adding to your `/etc/hosts` file.

## Theme Support

Automatically adapts to your Obsidian theme:

- **Dark Theme**: One Dark-inspired colors
- **Light Theme**: GitHub-inspired colors

## Tips for CTF/Pentesting

1. **Use comprehensive scans** for best results:
   ```bash
   nmap -sV -sC -O -p- target
   ```

2. **The summary shows attack surfaces** - look for:
   - Critical ports (SMB 445, RDP 3389, SSH 22)
   - Outdated service versions
   - Vulnerability script findings

3. **Create a recon template**:
   ````markdown
   ## Reconnaissance

   ### Nmap Scan
   ```nmap
   [paste output here]
   ```

   ### Key Findings
   -
   ````

4. **Use the filter toolbar** to focus on what matters - hide closed ports and script noise when reviewing.

5. **Copy /etc/hosts entries** directly from the summary for easy target access.

## Keyboard Shortcuts

All interactive elements support keyboard navigation:
- `Tab` to navigate between buttons
- `Enter` or `Space` to activate
- Focus indicators show current selection

## Print Support

When printing or exporting to PDF:
- All sections expanded automatically
- Animations disabled
- Clean borders instead of colored backgrounds
- Copy buttons hidden

## Changelog

### v1.1.0

**Bug Fixes:**
- Fixed parsing bug where wrong variable was used in summary data extraction
- Fixed IPv6 and hostname overlap detection for proper highlighting
- Fixed vulnerability extraction to capture all CVEs on a single line
- Added null checks to prevent potential errors in host data access

**Improvements:**
- Added proper `onunload()` method for plugin lifecycle management
- Tightened traceroute regex pattern to reduce false positives
- Pre-compiled regex patterns for better performance
- Added error logging to clipboard operations
- Improved mobile accessibility with larger touch targets (44px minimum on touch devices)
- Added `position: relative` to code container for proper button positioning
- Added JSDoc documentation to key methods
- Optimized by caching line splits to avoid duplicate processing

**Configuration:**
- Updated minimum Obsidian version to 1.4.0

For detailed technical changes, see [fix_changelog.md](fix_changelog.md).

### v1.0.0
- Initial release

## License

MIT License - Feel free to modify and distribute.

## Support

Issues or feature requests? Open an issue on the project repository.

---

**Happy Hacking!**
