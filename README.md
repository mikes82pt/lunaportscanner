# Luna Port Listener

**Version:** v3.0 (Go Rewrite)  
**License:** Unlicensed

Luna Port Listener is a lightweight and fast Windows tool for scanning TCP and UDP ports.  
It supports both interactive mode and non-interactive silent mode, making it useful for quick checks or automated tasks.

## Executables

| Architecture | Filename |
|-------------|----------|
| 64-bit      | `lunaportlistener.exe` |
| 32-bit      | `lunaportlistener-x86.exe` |

## Features

- Fast multi-port scanning with concurrency
- Supports **TCP**, **UDP**, or **BOTH**
- Interactive prompt mode
- Silent non-interactive mode with logging
- Hostname resolution
- Port ranges and comma-separated lists
- Default protocol is **TCP**

## Usage

### Interactive Mode (default)

Run:

```
lunaportlistener.exe
```

You will be prompted for:

- Target IP or domain  
- Port(s), e.g.:  
  `80`  
  `443,8080`  
  `20-25`
- Protocol (`TCP` / `UDP` / `BOTH`)  
  *Press Enter = TCP default*

After each scan, you can choose to continue.

### Non-Interactive Silent Mode

Writes results to a log file:

```
lunaportlistener.exe -t example.com -p 80,443 -protocol BOTH
```

Output file example:

```
scan-example.com.log
```

#### Available Flags

| Flag | Description |
|------|-------------|
| `-t` | Target host (required) |
| `-p` | Ports, e.g. `22`, `80,443`, `20-25` |
| `-protocol` | `TCP` \| `UDP` \| `BOTH` (default: TCP) |
| `-timeout` | Timeout in seconds (default: `1.0`) |
| `-concurrency` | Scan threads (default: `200`) |
| `--version` | Show version and exit |

Example:

```
lunaportlistener.exe -t 192.168.1.10 -p 1-1024 -protocol TCP
```

Silent mode produces **no console output**.

## System Requirements

- Windows 8.1 or later  
- No installation required  
- No administrator privileges needed  


## Notes

- If protocol is omitted, TCP is used by default
- Silent mode always writes to a log file
- IPv6 support depends on system configuration
